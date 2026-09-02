// Minimal guest PID 1 for the AAASM-5812 virtiofs + vsock prototype pass.
//
// This is NOT a general-purpose init. It exists solely to prove, from
// *inside* the guest, that:
//   1. a virtiofs share configured on the host (VZVirtioFileSystemDevice)
//      can actually be mounted and read by the guest kernel, and
//   2. a vsock connection (VZVirtioSocketDevice / VZVirtioSocketListener on
//      the host) can actually be dialed and exchange bytes with the host.
//
// Everything is done with raw libc syscalls against a static musl binary —
// there is no shell, no libc-provided init machinery, no /proc, nothing
// beyond what these two checks need. All progress is written directly to an
// explicitly-opened console device fd (never Rust's std::io::stdout/println,
// which wraps fd 1 — fd 1 is not attached to anything when the kernel execs
// PID 1 out of an initramfs with no /dev nodes yet; see README).
//
// PID 1 must never exit (the kernel panics on "Attempted to kill init!"), so
// this parks in an infinite sleep loop once its checks are done; the host
// process tears the VM down on its own timeout.

use std::ffi::CString;
use std::os::unix::io::RawFd;

// AAASM-5837: the real host↔guest launch protocol, layered on top of the
// vsock connectivity `try_vsock` below already proved. See protocol.rs's own
// module documentation.
mod protocol;

// AF_VSOCK is not exposed by the `libc` crate for every target the same way
// glibc/musl headers define it, so the handful of constants this needs are
// spelled out directly against their stable Linux uAPI values
// (include/uapi/linux/vm_sockets.h).
const AF_VSOCK: i32 = 40;
const VMADDR_CID_HOST: u32 = 2;
const VSOCK_PORT: u32 = 5555;

#[repr(C)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

fn write_fd(fd: RawFd, msg: &str) {
    if fd < 0 {
        return;
    }
    unsafe {
        libc::write(fd, msg.as_ptr() as *const _, msg.len());
    }
}

/// Open the first working console device, trying the virtio-console tty
/// (`hvc0`, what this PoC's kernel cmdline uses — see ../README.md) before
/// falling back to the generic `/dev/console` node. Returns -1 if neither
/// exists yet (e.g. devtmpfs failed to mount), in which case output is
/// simply lost — there is nothing else to fall back to this early in boot.
fn open_console() -> RawFd {
    for path in ["/dev/hvc0", "/dev/console"] {
        let c = CString::new(path).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY) };
        if fd >= 0 {
            return fd;
        }
    }
    -1
}

fn mkdir_p(path: &str) {
    let c = CString::new(path).unwrap();
    unsafe {
        libc::mkdir(c.as_ptr(), 0o755);
    }
    // Ignore errors (most likely EEXIST — the initramfs cpio already
    // contains this directory).
}

fn mount(source: &str, target: &str, fstype: &str) -> i32 {
    let src = CString::new(source).unwrap();
    let tgt = CString::new(target).unwrap();
    let fst = CString::new(fstype).unwrap();
    unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, std::ptr::null()) }
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Load a kernel module via `finit_module(2)` from a `.ko` file packed into
/// the initramfs itself. This substitute Debian generic kernel builds
/// virtio_mmio/virtio_console/virtiofs/vsock as loadable modules rather than
/// built-in (`=m`, not `=y` — see ../README.md "Debian generic kernel"),
/// so unlike the LinuxKit substitute used in the prior pass, this kernel
/// reaches userspace with *no* working console or virtio transport at all
/// until these are inserted — unusual for a minimal-init environment with no
/// modprobe/udev, hence loading them by hand here in a fixed dependency
/// order (mmio before console; fuse before virtiofs; vsock before its
/// virtio transport) instead of relying on module auto-loading.
fn load_module(console: RawFd, path: &str) -> bool {
    let c_path = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        write_fd(
            console,
            &format!("[guest-init] modprobe: open {path} FAILED errno={}\n", errno()),
        );
        return false;
    }
    let params = CString::new("").unwrap();
    let rc = unsafe { libc::syscall(libc::SYS_finit_module, fd, params.as_ptr(), 0) };
    unsafe {
        libc::close(fd);
    }
    if rc != 0 {
        write_fd(
            console,
            &format!("[guest-init] modprobe: finit_module {path} FAILED errno={}\n", errno()),
        );
        return false;
    }
    write_fd(console, &format!("[guest-init] modprobe: {path} OK\n"));
    true
}

fn try_virtiofs(console: RawFd, tag: &str, mountpoint: &str) {
    mkdir_p(mountpoint);
    let rc = mount(tag, mountpoint, "virtiofs");
    if rc != 0 {
        write_fd(
            console,
            &format!(
                "[guest-init] virtiofs mount FAILED: tag={tag} target={mountpoint} errno={}\n",
                errno()
            ),
        );
        return;
    }
    write_fd(
        console,
        &format!("[guest-init] virtiofs mount OK: tag={tag} -> {mountpoint}\n"),
    );

    let marker_path = format!("{mountpoint}/marker.txt");
    let c_path = CString::new(marker_path.clone()).unwrap();
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        write_fd(
            console,
            &format!(
                "[guest-init] virtiofs marker READ FAILED: {marker_path} errno={}\n",
                errno()
            ),
        );
        return;
    }
    let mut buf = [0u8; 512];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    unsafe {
        libc::close(fd);
    }
    if n < 0 {
        write_fd(console, "[guest-init] virtiofs marker read() failed\n");
        return;
    }
    let content = String::from_utf8_lossy(&buf[..n as usize]);
    write_fd(
        console,
        &format!("[guest-init] virtiofs marker CONTENT: {}\n", content.trim_end()),
    );
    write_fd(console, "[guest-init] VIRTIOFS-OK\n");
}

/// AAASM-5812 AC "a path outside [the share] is verified unreachable from
/// the guest… structurally absent, not merely policy-denied": attempt to
/// open a *fixed*-name marker file *inside* the virtiofs mount that the
/// host placed one level *above* the exported directory (see
/// `main.swift`'s "OUTSIDE-share negative-control file"), not a `..`
/// traversal off the mountpoint — `..` at a virtiofs mount root re-enters
/// the guest's own rootfs and never reaches the host at all, so it would
/// report ENOENT unconditionally regardless of how the export is scoped;
/// that version shipped in this pass's first cut and was caught in review
/// as a probe that cannot fail (see README "AC closure" for the
/// correction). This version has a real failure mode: if the export were
/// ever misconfigured to include the shared directory's parent rather than
/// the directory itself, this exact in-mount path would resolve and
/// open() would succeed.
fn try_virtiofs_negative_control(console: RawFd, mountpoint: &str) {
    let probe_path = format!("{mountpoint}/outside-marker.txt");
    let c_path = CString::new(probe_path.clone()).unwrap();
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if fd >= 0 {
        // This is the actual security failure this control exists to
        // catch: a file that only exists one level above the intended
        // export root is visible inside the mount.
        unsafe {
            libc::close(fd);
        }
        write_fd(
            console,
            &format!("[guest-init] VIRTIOFS-NEGATIVE-CONTROL-FAILED: {probe_path} opened successfully\n"),
        );
        return;
    }
    let err = errno();
    write_fd(
        console,
        &format!(
            "[guest-init] virtiofs negative control: open({probe_path}) FAILED errno={err} ({})\n",
            if err == libc::ENOENT { "ENOENT" } else { "not ENOENT" }
        ),
    );
    if err == libc::ENOENT {
        write_fd(console, "[guest-init] VIRTIOFS-NEGATIVE-CONTROL-OK\n");
    }
}

/// Run `program` as a child of this PID 1, with `argv` as its own argument
/// vector (everything after `program`'s own path). `fork`+`exec` rather than
/// replacing this process: PID 1 must never exit, and `aa-isolation-launch`
/// itself may `execve` all the way into the confined program on success, so
/// only a child of PID 1 can safely run either.
///
/// The child's stdout/stderr are duped onto `console` before `execv`, so
/// whatever `program` prints — a launcher refusal line
/// (`FAILURE_MARKER`, written to stderr) or a confined program's own
/// output — reaches the same captured console log this PoC already uses for
/// VIRTIOFS-OK/VSOCK-OK.
fn run_child(console: RawFd, label: &str, program: &str, argv: &[&str]) {
    write_fd(console, &format!("[guest-init] === {label} ===\n"));

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        write_fd(console, &format!("[guest-init] fork() FAILED errno={}\n", errno()));
        return;
    }
    if pid == 0 {
        // Child.
        unsafe {
            libc::dup2(console, 1);
            libc::dup2(console, 2);
        }
        let path = CString::new(program).unwrap();
        let argv_c: Vec<CString> = std::iter::once(path.clone())
            .chain(argv.iter().map(|a| CString::new(*a).unwrap()))
            .collect();
        let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        unsafe {
            libc::execv(path.as_ptr(), argv_ptrs.as_ptr());
        }
        // Only reached if execv itself failed (e.g. binary missing).
        write_fd(
            console,
            &format!("[guest-init] {program} execv() FAILED errno={}\n", errno()),
        );
        unsafe {
            libc::_exit(127);
        }
    }

    // Parent: wait for the child (`program`, or whatever it exec'd into) to
    // finish, then report how it ended.
    let mut status: i32 = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    if libc::WIFEXITED(status) {
        write_fd(
            console,
            &format!(
                "[guest-init] test '{label}' exited status={}\n",
                libc::WEXITSTATUS(status)
            ),
        );
    } else if libc::WIFSIGNALED(status) {
        write_fd(
            console,
            &format!(
                "[guest-init] test '{label}' killed by signal={}\n",
                libc::WTERMSIG(status)
            ),
        );
    } else {
        write_fd(
            console,
            &format!("[guest-init] test '{label}' ended with raw status={status}\n"),
        );
    }
}

fn main() {
    // devtmpfs gives us /dev/hvc0 and /dev/console without needing to know
    // their major/minor numbers ourselves. devtmpfs reacts to devices
    // registered *after* this mount too, so nodes for modules inserted below
    // (hvc0 from virtio_console, etc.) still appear via this same mount.
    mkdir_p("/dev");
    let _ = mount("devtmpfs", "/dev", "devtmpfs");

    // No console exists at all until virtio_mmio (transport) and
    // virtio_console (the actual /dev/hvc0 driver) are loaded — write_fd
    // silently drops output while console is still -1.
    let no_console: RawFd = -1;
    load_module(no_console, "/lib/modules/virtio_mmio.ko");
    load_module(no_console, "/lib/modules/virtio_console.ko");

    let console = open_console();
    write_fd(console, "[guest-init] GUEST-INIT-START pid1 up, devtmpfs mounted\n");
    write_fd(
        console,
        "[guest-init] modprobe: virtio_mmio + virtio_console loaded pre-console\n",
    );

    load_module(console, "/lib/modules/fuse.ko");
    load_module(console, "/lib/modules/virtiofs.ko");
    load_module(console, "/lib/modules/vsock.ko");
    load_module(console, "/lib/modules/vmw_vsock_virtio_transport_common.ko");
    load_module(console, "/lib/modules/vmw_vsock_virtio_transport.ko");

    try_virtiofs(console, "aa-share", "/mnt/share");
    try_virtiofs_negative_control(console, "/mnt/share");
    // AAASM-5837: try_vsock's fixed hello/reply used to run here as a
    // standalone vsock-connectivity proof. It now conflicts with the real
    // protocol below rather than complementing it: the host side (Swift's
    // VsockListenerDelegate, in --control-socket mode) pumps every incoming
    // vsock connection's bytes to a Rust listener expecting exactly one
    // connection speaking framed `Message`s — a second, earlier connection
    // sending the unframed greeting is indistinguishable from a wire error
    // to that listener (confirmed on real hardware: `WrongMagic`). The new
    // protocol's own `GuestReady` message proves vsock connectivity at
    // least as rigorously (a real two-way exchange, not just one byte
    // round trip) — see protocol.rs.

    // AAASM-5812 AC "the primary security boundary at this layer" — the
    // authoritative enumeration of what is actually mounted, so the claim
    // above ("exactly one virtiofs share") is asserted over the guest's own
    // mount table, not inferred only from one open() attempt succeeding or
    // failing. Requires /proc, which nothing before this point has needed.
    mkdir_p("/proc");
    let _ = mount("proc", "/proc", "proc");
    run_child(
        console,
        "proc-mounts (virtiofs scope evidence)",
        "/usr/local/bin/busybox",
        &["cat", "/proc/mounts"],
    );

    // AAASM-5812 "aa-isolation-launch cross-compile" pass.
    //
    // Positive control, run first: exec busybox *directly*, with no
    // aa-isolation-launch involved at all. Every one of the three
    // aa-isolation-launch scenarios below refuses before ever calling
    // execve on busybox (see the Landlock finding in ../README.md), so
    // without this control run, nothing in this guest ever actually proves
    // busybox is present, executable, the right architecture, that
    // static-pie loads on this kernel, or that /etc/testfile has the
    // expected content — the three refusal scenarios would look byte-
    // identical whether or not any of that were true. Expected:
    // 'exited status=0' and the testfile's own marker line echoed back.
    run_child(
        console,
        "busybox-direct (positive control)",
        "/usr/local/bin/busybox",
        &["cat", "/etc/testfile"],
    );

    // AAASM-5849 (ext4 assembly retry pass): the guest's Alpine-derived
    // toolchain layer (git, python3, /bin/sh) has never been exec'd inside
    // a real VZ guest before this pass — only under `docker import` on the
    // host (see README "Guest dev toolchain (AAASM-5849)"). The four
    // aa-isolation-launch scenarios below all refuse pre-flight on this
    // substitute kernel (no Landlock), so — same reasoning as the
    // busybox-direct control above — nothing else in this guest's boot
    // sequence would otherwise prove git/python3 are present, the right
    // architecture, or functional here specifically. Direct exec, bypassing
    // aa-isolation-launch entirely, same as busybox-direct.
    run_child(
        console,
        "git-direct (positive control)",
        "/usr/bin/git",
        &["--version"],
    );
    run_child(
        console,
        "python3-direct (positive control)",
        "/usr/bin/python3",
        &["-c", "import hashlib; print(hashlib.sha256(b'aaasm-5849').hexdigest())"],
    );
    // /bin/sh is a symlink to Alpine's own /bin/busybox (the real file the
    // toolchain tar carries), distinct from the fixed set's own
    // /usr/local/bin/busybox — same absolute-symlink family as the
    // /sbin/init bug this pass fixed in build-guest-rootfs.sh, so it is
    // worth exercising specifically rather than assuming it resolves the
    // same way just because busybox-direct above does.
    run_child(
        console,
        "sh-direct (positive control)",
        "/bin/sh",
        &["-c", "echo aaasm-5849-sh-ok"],
    );

    // Now the real, unmodified aa-isolation-launch binary, against three
    // scenarios, to characterize what it can actually enforce on this
    // particular substitute guest kernel — see ../README.md
    // "aa-isolation-launch cross-compile" for what each one is expected to
    // show and why.
    run_child(
        console,
        "aa-isolation-launch test: no-grants",
        "/usr/local/bin/aa-isolation-launch",
        &["--", "/usr/local/bin/busybox", "true"],
    );
    // AAASM-5813 prerequisite: on the first Landlock-capable kernel this PoC
    // has had (see ../README.md), this scenario surfaced a real gap in its
    // own test design — `--fs-read=/etc` grants Landlock's read-rights set
    // (which includes Execute, see `landlock::Access::from_read`) on /etc,
    // but the busybox binary being exec'd lives at /usr/local/bin, never
    // covered by any grant in the original three scenarios. Every one of
    // them denied exec outright, including this one, until this fix added
    // an explicit grant for busybox's own path — without it, this scenario
    // could never have demonstrated a successful confined execution on any
    // kernel, real or substitute; nothing here was truly validated end to
    // end before now.
    run_child(
        console,
        "aa-isolation-launch test: fs-read+fs-write",
        "/usr/local/bin/aa-isolation-launch",
        &[
            "--fs-read=/etc",
            "--fs-read=/usr/local/bin",
            "--fs-write=/tmp",
            "--",
            "/usr/local/bin/busybox",
            "cat",
            "/etc/testfile",
        ],
    );
    run_child(
        console,
        "aa-isolation-launch test: syscall-filter",
        "/usr/local/bin/aa-isolation-launch",
        &[
            "--syscall-filter",
            "--syscall-allow=read",
            "--syscall-allow=write",
            "--syscall-allow=close",
            "--syscall-allow=exit",
            "--syscall-allow=exit_group",
            "--",
            "/usr/local/bin/busybox",
            "true",
        ],
    );

    // AAASM-5813 prerequisite: on a Landlock-capable guest kernel, the three
    // scenarios above stop refusing pre-flight (see ../README.md) — this
    // fourth scenario is the one that actually exercises enforcement, not
    // just installation. Same fs-read=/etc,fs-write=/tmp grant as scenario
    // 2, but the target is /root/outside-grant.txt — outside both granted
    // paths. If Landlock is doing its job, aa-isolation-launch installs the
    // ruleset and execs busybox successfully (no refusal marker), and
    // busybox itself gets a real EACCES trying to open the file — a
    // genuinely different, enforcement-level failure signature than the
    // "kernel cannot handle" refusals above, and the negative half of the
    // AC this pass exists to close (fs-read+fs-write is the positive half).
    run_child(
        console,
        "aa-isolation-launch test: fs-read+fs-write, target OUTSIDE grant",
        "/usr/local/bin/aa-isolation-launch",
        &[
            "--fs-read=/etc",
            "--fs-read=/usr/local/bin",
            "--fs-write=/tmp",
            "--",
            "/usr/local/bin/busybox",
            "cat",
            "/root/outside-grant.txt",
        ],
    );

    // AAASM-5849 (Landlock-capable-kernel pass): the toolchain binaries
    // added this pass (git, python3, /bin/sh) have only ever been exercised
    // via direct exec (the *-direct controls above) or via docker import on
    // the host — never through the real aa-isolation-launch protocol under
    // actual Landlock enforcement, because every kernel through the prior
    // pass lacked CONFIG_SECURITY_LANDLOCK. On a Landlock-capable kernel,
    // these two scenarios are the toolchain's own equivalent of the
    // busybox fs-read+fs-write/outside-grant pair above: same
    // ControlledPair shape (identical grants and program, only the write
    // target differs), but exercising a *write* denial specifically, since
    // every existing scenario's negative half was a read denial.
    //
    // Unlike busybox (static, no dependencies), git/python3 are
    // dynamically linked against the Alpine toolchain's musl libc — `ldd`
    // against the actual extracted binaries shows both need
    // /lib/ld-musl-aarch64.so.1 (the ELF interpreter) plus per-binary
    // shared libraries under /usr/lib (libpython3.12.so.1.0,
    // libpcre2-8.so.0) and /lib (libz.so.1). The kernel opens the
    // interpreter as part of the same execve() that loads the program
    // itself, so a ruleset granting only the program's own directory (the
    // busybox scenarios' shape) makes execve() itself fail with EACCES —
    // indistinguishable, from this binary's own output alone, from a grant
    // that was simply missing the program's directory, until traced back
    // to `ldd` (found the hard way: the first version of this scenario
    // granted only /usr/bin and refused pre-exec, identically to
    // no-grants, until this was diagnosed). --fs-read must cover /lib and
    // /usr/lib too, not just /usr/bin, for a dynamically-linked program to
    // exec at all under Landlock.
    run_child(
        console,
        "aa-isolation-launch test: python3 fs-write, target INSIDE grant",
        "/usr/local/bin/aa-isolation-launch",
        &[
            "--fs-read=/usr/bin",
            "--fs-read=/lib",
            "--fs-read=/usr/lib",
            "--fs-write=/tmp",
            "--",
            "/usr/bin/python3",
            "-c",
            "open('/tmp/aaasm-5849-write-ok.txt', 'w').write('landlock-write-ok')",
        ],
    );
    run_child(
        console,
        "aa-isolation-launch test: python3 fs-write, target OUTSIDE grant",
        "/usr/local/bin/aa-isolation-launch",
        &[
            "--fs-read=/usr/bin",
            "--fs-read=/lib",
            "--fs-read=/usr/lib",
            "--fs-write=/tmp",
            "--",
            "/usr/bin/python3",
            "-c",
            "open('/root/aaasm-5849-write-denied.txt', 'w').write('should-not-write')",
        ],
    );
    // Same grant shape, git instead of python3 — the ticket's own title
    // names git specifically ("cannot run arbitrary agent commands
    // (python/git/node/etc)"); this is that command, exec'd through the
    // real launch protocol rather than guest-init's direct-exec control.
    run_child(
        console,
        "aa-isolation-launch test: git --version",
        "/usr/local/bin/aa-isolation-launch",
        &[
            "--fs-read=/usr/bin",
            "--fs-read=/lib",
            "--fs-read=/usr/lib",
            "--",
            "/usr/bin/git",
            "--version",
        ],
    );

    write_fd(console, "[guest-init] GUEST-INIT-DONE, boot diagnostics complete\n");

    // AAASM-5837: real launches from here on. `dial_and_serve_forever` never
    // returns (see its own docs) — it is this process's "PID 1 must never
    // exit" mechanism, replacing the fixed sleep-loop this line used to end
    // on.
    protocol::dial_and_serve_forever(console);
}
