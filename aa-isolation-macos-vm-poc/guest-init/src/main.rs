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

fn try_vsock(console: RawFd) {
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        write_fd(
            console,
            &format!("[guest-init] vsock socket() FAILED errno={}\n", errno()),
        );
        return;
    }

    let addr = SockaddrVm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: VSOCK_PORT,
        svm_cid: VMADDR_CID_HOST,
        svm_zero: [0; 4],
    };

    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as u32,
        )
    };
    if rc != 0 {
        write_fd(
            console,
            &format!(
                "[guest-init] vsock connect() to host CID={VMADDR_CID_HOST} port={VSOCK_PORT} FAILED errno={}\n",
                errno()
            ),
        );
        unsafe {
            libc::close(fd);
        }
        return;
    }
    write_fd(
        console,
        &format!("[guest-init] vsock connect() OK (cid={VMADDR_CID_HOST} port={VSOCK_PORT})\n"),
    );

    let greeting = b"hello-from-guest-vsock\n";
    unsafe {
        libc::write(fd, greeting.as_ptr() as *const _, greeting.len());
    }
    write_fd(console, "[guest-init] vsock greeting sent\n");

    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    if n > 0 {
        let reply = String::from_utf8_lossy(&buf[..n as usize]);
        write_fd(
            console,
            &format!("[guest-init] vsock host reply: {}\n", reply.trim_end()),
        );
        write_fd(console, "[guest-init] VSOCK-OK\n");
    } else {
        write_fd(
            console,
            &format!("[guest-init] vsock read() got n={n} errno={}\n", errno()),
        );
    }

    unsafe {
        libc::close(fd);
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
    write_fd(console, "[guest-init] modprobe: virtio_mmio + virtio_console loaded pre-console\n");

    load_module(console, "/lib/modules/fuse.ko");
    load_module(console, "/lib/modules/virtiofs.ko");
    load_module(console, "/lib/modules/vsock.ko");
    load_module(console, "/lib/modules/vmw_vsock_virtio_transport_common.ko");
    load_module(console, "/lib/modules/vmw_vsock_virtio_transport.ko");

    try_virtiofs(console, "aa-share", "/mnt/share");
    try_vsock(console);

    write_fd(console, "[guest-init] GUEST-INIT-DONE, parking\n");

    // PID 1 must never return/exit.
    loop {
        unsafe {
            libc::sleep(3600);
        }
    }
}
