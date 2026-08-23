//! Drives one Virtualization.framework guest through the AAASM-5837 launch
//! protocol, via the existing Swift helper (`aa-isolation-macos-vm-poc`).
//!
//! # Why a subprocess + Unix-domain socket, not Rust dialing vsock directly
//!
//! On macOS there is no user-space `AF_VSOCK` for a `VZVirtualMachine`
//! guest — `VZVirtioSocketDevice`/`VZVirtioSocketListener` exist only inside
//! the process holding the `VZVirtualMachine` object itself. This module
//! spawns the Swift helper as a child process and listens on a Unix-domain
//! socket the helper's own `--control-socket` pumps the guest connection to
//! byte-for-byte (see `main.swift`'s `VsockListenerDelegate`) — the smallest
//! diff that keeps the Swift side entirely ignorant of the wire protocol
//! (see `aa-isolation-vm-proto`'s crate docs).
//!
//! `listener.accept()` returning *is* the "guest is connected" signal — no
//! separate readiness poll is needed.

use std::io::{BufReader, BufWriter};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aa_isolation_vm_proto::{read_frame, write_frame, FrameError, Message, PROTOCOL_VERSION};

/// How long [`boot`] waits for the guest to connect before giving up and
/// tearing the helper down. Generous relative to every real boot this Epic
/// has measured (low single-digit seconds) without being unbounded — see
/// [`IsolationBackend::prepare`](aa_isolation::IsolationBackend::prepare)'s
/// contract: a caller that hangs here has no way to know whether anything is
/// running.
const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The fixed cmdline every prior pass's real-hardware verification used —
/// see `aa-isolation-macos-vm-poc/README.md`'s "virtio-block root disk"
/// section. Not configurable in this pass: changing it is a substrate
/// concern (AAASM-5812), not something a launch's own spec should be able to
/// influence.
const GUEST_CMDLINE: &str = "console=hvc0 root=/dev/vda rw rootfstype=ext4 init=/sbin/init";

/// Paths to the artifacts this backend needs on the host — the helper
/// binary (already codesigned with `com.apple.security.virtualization`),
/// the Landlock-capable guest kernel, and the guest rootfs image.
///
/// # Why these are environment variables and not compiled-in paths
///
/// All three are large, host-specific, gitignored build artifacts (see
/// `aa-isolation-macos-vm-poc/.gitignore`) produced by scripts, not shipped
/// in the repository or the `aasm` binary. A fixed compiled-in path would be
/// wrong on every machine that built them somewhere else. This is also
/// exactly what [`MacosVmBackend::discover`](crate::MacosVmBackend::discover)
/// probes to decide `Available`/`Unavailable` — see that function.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Path to the codesigned `aa-isolation-macos-vm-poc` helper binary.
    pub helper_path: PathBuf,
    /// Path to the Landlock-capable guest kernel
    /// (`scripts/build-landlock-kernel.sh`'s output).
    pub kernel_path: PathBuf,
    /// Path to the guest rootfs image (`scripts/build-guest-rootfs.sh`'s
    /// output).
    pub rootfs_path: PathBuf,
}

impl VmConfig {
    /// Environment variable naming the helper binary.
    pub const ENV_HELPER: &'static str = "AA_ISOLATION_MACOS_VM_HELPER";
    /// Environment variable naming the guest kernel.
    pub const ENV_KERNEL: &'static str = "AA_ISOLATION_MACOS_VM_KERNEL";
    /// Environment variable naming the guest rootfs image.
    pub const ENV_ROOTFS: &'static str = "AA_ISOLATION_MACOS_VM_ROOTFS";

    /// Read the three paths from their environment variables, requiring each
    /// named file to actually exist.
    ///
    /// Returns `None` — not an error — when any prerequisite is absent: this
    /// is [`discover`](crate::MacosVmBackend::discover)'s own probe, and
    /// "not configured" is an ordinary, expected `Unavailable` reason on
    /// most hosts, not a failure this function itself reports as one.
    pub fn from_env() -> Option<Self> {
        let helper_path = PathBuf::from(std::env::var(Self::ENV_HELPER).ok()?);
        let kernel_path = PathBuf::from(std::env::var(Self::ENV_KERNEL).ok()?);
        let rootfs_path = PathBuf::from(std::env::var(Self::ENV_ROOTFS).ok()?);
        if !helper_path.is_file() || !kernel_path.is_file() || !rootfs_path.is_file() {
            return None;
        }
        Some(Self {
            helper_path,
            kernel_path,
            rootfs_path,
        })
    }
}

/// A booted guest, connected and speaking the launch protocol.
pub struct VmSession {
    helper: Child,
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
    /// Free-text diagnostics the guest reported in its `GuestReady` message.
    pub guest_notes: Vec<String>,
    control_socket_dir: PathBuf,
}

impl VmSession {
    /// Send a framed [`Message`] to the guest.
    pub fn send(&mut self, message: &Message) -> Result<(), FrameError> {
        write_frame(&mut self.writer, message)
    }

    /// Block until the guest sends its next framed [`Message`].
    pub fn recv(&mut self) -> Result<Message, FrameError> {
        read_frame(&mut self.reader)
    }

    /// Bound how long [`recv`](Self::recv) can block before giving up.
    ///
    /// Used by [`crate::probe::measure`], which runs inside
    /// [`crate::MacosVmBackend::discover`] (including on the CLI's
    /// `--dry-run` preview path) — a wedged guest must not be able to hang a
    /// caller that has no way to know whether anything is running while it
    /// waits. `None` restores the unbounded default a real launch's own
    /// session still wants (its caller decides how long to wait via
    /// [`aa_isolation::IsolationBackend::wait_for_exit`]'s own contract, not
    /// this connection's read timeout).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.reader.get_ref().set_read_timeout(timeout)
    }
}

impl Drop for VmSession {
    fn drop(&mut self) {
        // Any ambiguity ⇒ destroy the VM (see this crate's docs on
        // failure/refusal semantics): dropping the writer half closes the
        // Unix-domain socket, which the helper observes as EOF and stops
        // the VM on (see `main.swift`'s pump-ended watcher) — but this
        // process does not depend on that happening cleanly. Killing the
        // helper directly is what actually guarantees nothing from this
        // session keeps running after this value is gone.
        let _ = self.helper.kill();
        let _ = self.helper.wait();
        let _ = std::fs::remove_dir_all(&self.control_socket_dir);
    }
}

/// Boot a guest via `config`, sharing `share_dir` (when given) at
/// [`crate::paths::GUEST_SHARE_MOUNTPOINT`], and wait for it to connect and
/// send `GuestReady`.
///
/// # Errors
///
/// A `String` describing what failed — the caller ([`crate::MacosVmBackend`])
/// maps this to [`aa_isolation::SpawnError::Prepare`], since nothing is
/// running yet at any failure point this function can reach.
pub fn boot(config: &VmConfig, share_dir: Option<&Path>) -> Result<VmSession, String> {
    let control_socket_dir = std::env::temp_dir().join(format!(
        "aa-isolation-macos-vm-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&control_socket_dir)
        .map_err(|err| format!("could not create a scratch directory: {err}"))?;
    let control_socket_path = control_socket_dir.join("control.sock");

    let listener =
        UnixListener::bind(&control_socket_path).map_err(|err| format!("could not bind control socket: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("could not configure control socket: {err}"))?;

    let mut command = Command::new(&config.helper_path);
    command
        .arg("--kernel")
        .arg(&config.kernel_path)
        .arg("--no-initrd")
        .arg("--disk")
        .arg(&config.rootfs_path)
        .arg("--cmdline")
        .arg(GUEST_CMDLINE)
        .arg("--control-socket")
        .arg(&control_socket_path)
        .arg("--timeout")
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = share_dir {
        command.arg("--share-dir").arg(dir);
    } else {
        command.arg("--no-virtiofs");
    }

    let mut helper = command
        .spawn()
        .map_err(|err| format!("could not spawn the helper at {}: {err}", config.helper_path.display()))?;

    let deadline = Instant::now() + GUEST_CONNECT_TIMEOUT;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _addr)) => break stream,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if let Ok(Some(status)) = helper.try_wait() {
                    let _ = std::fs::remove_dir_all(&control_socket_dir);
                    return Err(format!("the helper exited before the guest connected: {status}"));
                }
                if Instant::now() >= deadline {
                    let _ = helper.kill();
                    let _ = helper.wait();
                    let _ = std::fs::remove_dir_all(&control_socket_dir);
                    return Err(format!(
                        "timed out after {}s waiting for the guest to connect",
                        GUEST_CONNECT_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => {
                let _ = helper.kill();
                let _ = helper.wait();
                let _ = std::fs::remove_dir_all(&control_socket_dir);
                return Err(format!("accept() on the control socket failed: {err}"));
            }
        }
    };
    stream
        .set_nonblocking(false)
        .map_err(|err| format!("could not configure the accepted connection: {err}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|err| format!("could not clone the connection: {err}"))?,
    );
    let writer = BufWriter::new(stream);

    let ready = read_frame(&mut reader).map_err(|err| {
        let _ = helper.kill();
        format!("failed to read GuestReady: {err}")
    })?;
    let Message::GuestReady {
        protocol_version,
        guest_notes,
    } = ready
    else {
        let _ = helper.kill();
        return Err(format!("expected GuestReady, got {ready:?}"));
    };
    if protocol_version != PROTOCOL_VERSION {
        let _ = helper.kill();
        return Err(format!(
            "guest speaks protocol version {protocol_version}, this build speaks {PROTOCOL_VERSION}"
        ));
    }

    Ok(VmSession {
        helper,
        reader,
        writer,
        guest_notes,
        control_socket_dir,
    })
}

/// A per-process-unique suffix for the scratch directory name, so two
/// sessions started by the same process in the same second cannot collide.
/// Not a security control — the directory only ever holds a Unix-domain
/// socket this process itself created.
fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
