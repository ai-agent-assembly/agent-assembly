//! Real-hardware verification harness for AAASM-5837's host↔guest launch
//! protocol.
//!
//! Not part of this crate's library surface — a standalone binary because
//! proving the protocol works means actually booting the VM
//! (`aa-isolation-macos-vm-poc`'s Swift helper) and driving a real vsock
//! connection through it, which is PoC-verification scope, not something a
//! unit test can do. `aa-isolation-vm-proto/tests/` already holds the
//! no-VM-needed round-trip tests (frame encode/decode, `to_launcher_argv`
//! against the launcher's own parser); this binary is what proves the same
//! contract holds end to end, against the real guest.
//!
//! # Usage
//!
//! ```text
//! cargo run -p aa-isolation-vm-proto --bin protocol-harness -- \
//!   --helper <path to aa-isolation-macos-vm-poc binary, already codesigned> \
//!   --kernel <path to images-landlock-kernel/kernel> \
//!   --rootfs <path to images/guest-rootfs.img>
//! ```
//!
//! Boots the guest, accepts the pumped vsock connection, sends a
//! [`aa_isolation_vm_proto::Message::LaunchRequest`] for a real command
//! (`/usr/local/bin/busybox cat /etc/testfile`, matching the fixture every
//! prior PoC pass has used), and asserts the full sequence:
//! `GuestReady` → (this harness sends `LaunchRequest`) →
//! `LaunchAccepted` → `LaunchOutcome` with `disposition == Exited { code: 0 }`.
//! Prints each message as it arrives and exits non-zero on any deviation.

use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use aa_isolation_vm_proto::{read_frame, write_frame, Disposition, Message};

struct Args {
    helper: String,
    kernel: String,
    rootfs: String,
}

fn parse_args() -> Args {
    let mut helper = None;
    let mut kernel = None;
    let mut rootfs = None;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--helper" => helper = iter.next(),
            "--kernel" => kernel = iter.next(),
            "--rootfs" => rootfs = iter.next(),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let (Some(helper), Some(kernel), Some(rootfs)) = (helper, kernel, rootfs) else {
        eprintln!("usage: protocol-harness --helper <path> --kernel <path> --rootfs <path>");
        std::process::exit(2);
    };
    Args { helper, kernel, rootfs }
}

/// Kills the helper process on drop, so a harness that fails or panics
/// midway never leaves a VM running in the background — the same
/// no-silent-fallback discipline the protocol itself is held to applies to
/// the tool that verifies it.
struct HelperGuard(Child);

impl Drop for HelperGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() {
    let args = parse_args();

    let socket_dir = std::env::temp_dir().join(format!("aa-vm-proto-harness-{}", std::process::id()));
    std::fs::create_dir_all(&socket_dir).expect("create harness temp dir");
    let socket_path = socket_dir.join("control.sock");
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("bind control socket");
    listener
        .set_nonblocking(false)
        .expect("blocking listener: this harness accepts exactly one connection, sequentially");

    println!("[harness] listening on {}", socket_path.display());
    println!("[harness] spawning helper: {}", args.helper);

    let child = Command::new(&args.helper)
        .args([
            "--kernel",
            &args.kernel,
            "--no-initrd",
            "--disk",
            &args.rootfs,
            "--cmdline",
            "console=hvc0 root=/dev/vda rw rootfstype=ext4 init=/sbin/init",
            "--control-socket",
            socket_path.to_str().expect("temp path is valid UTF-8"),
            "--timeout",
            "0",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn helper process");
    let _guard = HelperGuard(child);

    println!("[harness] waiting for the guest to connect (accept() is the readiness signal)...");
    let (stream, _addr) = listener.accept().expect("accept the guest's pumped connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set read timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream for reading"));
    let mut writer = BufWriter::new(stream);

    let ready = read_frame(&mut reader).expect("read GuestReady");
    println!("[harness] received: {ready:?}");
    let Message::GuestReady { protocol_version, .. } = &ready else {
        eprintln!("[harness] FAIL: expected GuestReady, got {ready:?}");
        std::process::exit(1);
    };
    assert_eq!(
        *protocol_version,
        aa_isolation_vm_proto::PROTOCOL_VERSION,
        "guest protocol version mismatch"
    );

    let request = Message::LaunchRequest {
        request_id: "harness-1".to_string(),
        program: "/usr/local/bin/busybox".to_string(),
        args: vec!["cat".to_string(), "/etc/testfile".to_string()],
        env: std::collections::BTreeMap::new(),
        working_dir: None,
        fs_read: vec!["/etc".to_string()],
        fs_write: vec!["/tmp".to_string()],
        syscall_filter: None,
    };
    println!("[harness] sending: {request:?}");
    write_frame(&mut writer, &request).expect("write LaunchRequest");

    let accepted = read_frame(&mut reader).expect("read LaunchAccepted");
    println!("[harness] received: {accepted:?}");
    let Message::LaunchAccepted { request_id } = &accepted else {
        eprintln!("[harness] FAIL: expected LaunchAccepted, got {accepted:?}");
        std::process::exit(1);
    };
    assert_eq!(request_id, "harness-1");

    let outcome = read_frame(&mut reader).expect("read LaunchOutcome");
    println!("[harness] received: {outcome:?}");
    let Message::LaunchOutcome {
        disposition,
        launcher_refused,
        implicit_grants,
        stdout,
        ..
    } = &outcome
    else {
        eprintln!("[harness] FAIL: expected LaunchOutcome, got {outcome:?}");
        std::process::exit(1);
    };

    let mut ok = true;
    if *disposition != (Disposition::Exited { code: 0 }) {
        eprintln!("[harness] FAIL: expected Exited{{code: 0}}, got {disposition:?}");
        ok = false;
    }
    if *launcher_refused {
        eprintln!("[harness] FAIL: the launcher refused this launch, expected it to succeed");
        ok = false;
    }
    if !implicit_grants.iter().any(|g| g == "/usr/local/bin/busybox") {
        eprintln!("[harness] FAIL: implicit_grants does not name the program path: {implicit_grants:?}");
        ok = false;
    }
    let stdout_text = String::from_utf8_lossy(stdout);
    if !stdout_text.contains("aa-isolation-launch-guest-rootfs-test-marker") {
        eprintln!("[harness] FAIL: stdout does not contain the expected marker: {stdout_text:?}");
        ok = false;
    }

    if ok {
        println!("[harness] PASS: full launch round trip verified against real hardware");
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
