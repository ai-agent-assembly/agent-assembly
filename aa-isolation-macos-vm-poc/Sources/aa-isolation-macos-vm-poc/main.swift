// AAASM-5812 PoC — prove Virtualization.framework can boot a Linux kernel
// on this host with real console output reaching the host process.
//
// Extended (still AAASM-5812, next bounded increment) to prototype virtiofs
// directory sharing and the vsock control channel against the same
// substitute kernel, with a purpose-built guest-init binary (../guest-init)
// as the initramfs's PID 1 so both are verified guest-side, not just
// host-side config acceptance. Still out of scope: NAT networking, running
// aa-isolation-launch in-guest, the final kernel-sourcing decision. See
// README.md for what this proves and what it does not.

import Foundation
import Virtualization

// MARK: - CLI arguments

struct Args {
    var kernelPath: String
    var initrdPath: String?
    var diskPath: String?
    var cmdLine: String
    var memoryMiB: UInt64
    var cpuCount: Int
    var timeoutSeconds: Double
    var bootMarker: String?
    var shareDir: String?
    var shareTag: String
    var vsockPort: UInt32
    var enableVirtiofs: Bool
    var enableVsock: Bool
    // AAASM-5837: when set, the guest vsock connection is pumped byte-for-byte
    // to/from a Unix-domain socket at this path instead of replying with the
    // fixed "hello-from-host-vsock" greeting. This process never parses what
    // crosses the pump — see VsockPumpDelegate's own documentation for why
    // protocol knowledge belongs entirely in the Rust process on the other
    // end of the socket, not here.
    var controlSocketPath: String?
}

func parseArgs() -> Args {
    var kernelPath = "images/vmlinuz-virt"
    var initrdPath: String? = "images/initramfs-virt"
    var diskPath: String? = nil
    var cmdLine = "console=hvc0"
    var memoryMiB: UInt64 = 768
    var cpuCount = 2
    var timeoutSeconds = 45.0
    var bootMarker: String? = nil
    var shareDir: String? = nil
    var shareTag = "aa-share"
    var vsockPort: UInt32 = 5555
    var enableVirtiofs = true
    var enableVsock = true
    var controlSocketPath: String? = nil

    var args = CommandLine.arguments.dropFirst().makeIterator()
    while let arg = args.next() {
        switch arg {
        case "--kernel":
            kernelPath = args.next() ?? kernelPath
        case "--initrd":
            initrdPath = args.next() ?? initrdPath
        case "--no-initrd":
            initrdPath = nil
        case "--disk":
            diskPath = args.next()
        case "--cmdline":
            cmdLine = args.next() ?? cmdLine
        case "--memory-mib":
            if let v = args.next(), let n = UInt64(v) { memoryMiB = n }
        case "--cpus":
            if let v = args.next(), let n = Int(v) { cpuCount = n }
        case "--timeout":
            if let v = args.next(), let n = Double(v) { timeoutSeconds = n }
        case "--boot-marker":
            bootMarker = args.next()
        case "--share-dir":
            shareDir = args.next()
        case "--share-tag":
            shareTag = args.next() ?? shareTag
        case "--vsock-port":
            if let v = args.next(), let n = UInt32(v) { vsockPort = n }
        case "--no-virtiofs":
            enableVirtiofs = false
        case "--no-vsock":
            enableVsock = false
        case "--control-socket":
            controlSocketPath = args.next()
        default:
            FileHandle.standardError.write("unknown argument: \(arg)\n".data(using: .utf8)!)
        }
    }

    return Args(
        kernelPath: kernelPath,
        initrdPath: initrdPath,
        diskPath: diskPath,
        cmdLine: cmdLine,
        memoryMiB: memoryMiB,
        cpuCount: cpuCount,
        timeoutSeconds: timeoutSeconds,
        bootMarker: bootMarker,
        shareDir: shareDir,
        shareTag: shareTag,
        vsockPort: vsockPort,
        enableVirtiofs: enableVirtiofs,
        enableVsock: enableVsock,
        controlSocketPath: controlSocketPath
    )
}

let args = parseArgs()

func log(_ msg: String) {
    FileHandle.standardError.write("[poc] \(msg)\n".data(using: .utf8)!)
}

func fail(_ msg: String) -> Never {
    log("FAIL: \(msg)")
    exit(1)
}

// MARK: - Console capture

// The guest's serial console is wired to a pipe (not stdout directly) so we
// can both mirror it live to the host terminal AND scan it for a boot marker
// / retain a trimmed capture for the README evidence, without the two uses
// racing over the same FileHandle.
let consolePipe = Pipe()
var capturedOutput = Data()
let captureLock = NSLock()

consolePipe.fileHandleForReading.readabilityHandler = { handle in
    let data = handle.availableData
    guard !data.isEmpty else { return }
    captureLock.lock()
    capturedOutput.append(data)
    captureLock.unlock()
    FileHandle.standardOutput.write(data)
}

// MARK: - VM configuration

guard FileManager.default.fileExists(atPath: args.kernelPath) else {
    fail("kernel not found at \(args.kernelPath) — run scripts/fetch-images.sh first")
}
if let initrdPath = args.initrdPath {
    guard FileManager.default.fileExists(atPath: initrdPath) else {
        fail("initrd not found at \(initrdPath) — run scripts/fetch-images.sh first")
    }
}
if let diskPath = args.diskPath {
    guard FileManager.default.fileExists(atPath: diskPath) else {
        fail("disk image not found at \(diskPath)")
    }
}

let kernelURL = URL(fileURLWithPath: args.kernelPath)

let bootLoader = VZLinuxBootLoader(kernelURL: kernelURL)
if let initrdPath = args.initrdPath {
    bootLoader.initialRamdiskURL = URL(fileURLWithPath: initrdPath)
}
bootLoader.commandLine = args.cmdLine

let config = VZVirtualMachineConfiguration()
config.bootLoader = bootLoader
config.cpuCount = args.cpuCount
config.memorySize = args.memoryMiB * 1024 * 1024

// MARK: - virtio-block root disk
//
// The substitute LinuxKit kernel used for this PoC has CONFIG_BLK_DEV_INITRD
// unset (confirmed by extracting its embedded IKCONFIG — see README.md
// "Debian generic kernel" / "virtio-block root disk") — it never unpacks a
// bootloader-supplied cpio initrd, matching pass 2's empirical finding. It
// does have CONFIG_VIRTIO_BLK=y and CONFIG_EXT4_FS=y built in, so a
// virtio-block root disk sidesteps the initramfs question entirely.
if let diskPath = args.diskPath {
    let diskURL = URL(fileURLWithPath: diskPath)
    do {
        let attachment = try VZDiskImageStorageDeviceAttachment(url: diskURL, readOnly: false)
        let blockConfig = VZVirtioBlockDeviceConfiguration(attachment: attachment)
        config.storageDevices = [blockConfig]
        log("disk:    \(diskPath) attached as virtio-blk (rw)")
    } catch {
        fail("could not attach disk \(diskPath): \(error)")
    }
}

let serialConfig = VZVirtioConsoleDeviceSerialPortConfiguration()
let serialAttachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: nil,
    fileHandleForWriting: consolePipe.fileHandleForWriting
)
serialConfig.attachment = serialAttachment
config.serialPorts = [serialConfig]

// No network, no storage devices, no NAT — deliberately still out of scope
// for this pass (see README).
config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

// MARK: - virtiofs directory sharing

// If the caller didn't supply --share-dir, create a scratch temp dir and
// drop a known marker file in it — the guest-init binary reads this file
// back over the virtiofs mount and echoes its content to the console, which
// is this PoC's guest-side proof (see README "Verified virtiofs" section).
var shareDirURL: URL? = nil
if args.enableVirtiofs {
    let dirPath: String
    if let given = args.shareDir {
        dirPath = given
    } else {
        let scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("aa-isolation-macos-vm-poc-share-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        let markerContents = "virtiofs-marker-\(UUID().uuidString)\n"
        try? markerContents.write(
            to: scratch.appendingPathComponent("marker.txt"), atomically: true, encoding: .utf8)
        log("virtiofs: created scratch share dir \(scratch.path) with marker.txt = \(markerContents.trimmingCharacters(in: .whitespacesAndNewlines))")
        dirPath = scratch.path
    }
    shareDirURL = URL(fileURLWithPath: dirPath, isDirectory: true)

    // AAASM-5812 AC "a path outside [the share] is verified unreachable
    // from the guest, structurally absent, not merely policy-denied":
    // a sibling file, one level *above* the exported directory, at a
    // FIXED name the guest checks for *inside* its mount
    // (`/mnt/share/outside-marker.txt`) — not via a `..` traversal.
    // `..` at a virtiofs mount root re-enters the guest's own rootfs,
    // never reaches the host at all, and would report ENOENT
    // unconditionally regardless of how the export is scoped — that
    // probe cannot fail and is not evidence (caught in review after
    // pass 5 first shipped it, see README "AC closure" for the
    // correction). Written unconditionally — including on the
    // `--share-dir` path, which previously skipped this entirely and made
    // the guest's ENOENT true only by the accident of no such file existing
    // anywhere, not because the export boundary held (caught in review a
    // second time, same class of bug). This version has a real failure
    // mode: if the export were ever misconfigured to include the shared
    // dir's *parent* rather than the dir itself, this file would actually
    // appear at that exact in-mount path, and the guest's open() would
    // succeed.
    let outsideMarkerName = "outside-marker.txt"
    let outsideMarkerContents = "outside-marker-\(UUID().uuidString)\n"
    let outsideMarkerURL = shareDirURL!.deletingLastPathComponent()
        .appendingPathComponent(outsideMarkerName)
    do {
        // AAASM-5870: `atomically: false`, deliberately. `shareDirURL`'s
        // parent is not a directory this process created or owns — every
        // concurrent boot on the host writes this same fixed-name marker
        // into whatever directory its own share dir happens to sit under,
        // which collides whenever two boots share a parent (e.g. two
        // `aasm run`s under the same project root, or — as measured in
        // this crate's own `probe`/`real_hardware.rs` — every boot's
        // scratch dir sitting directly under the one shared
        // `NSTemporaryDirectory()`/`std::env::temp_dir()`). `atomically:
        // true` writes a temp file *in that same shared parent* and
        // `rename()`s it into place; `atomically: false` opens and writes
        // the target path directly, with no extra file created and removed
        // in a directory this process does not control the concurrent use
        // of. This does not fix the concurrent write to the marker path
        // itself (harmless: the guest only checks `open()` success, never
        // content — see `guest-init`'s `try_virtiofs_negative_control`),
        // it only removes the create/rename churn in the shared parent.
        // Not confirmed as AAASM-5870's actual mechanism (that would need
        // a live concurrent-boot repro this pass's environment could not
        // run — see `vmm::BootLock`'s docs) — kept regardless because it
        // is a real defect in this process's own handling of a directory
        // it does not own, independent of whether it explains the
        // Virtualization.framework failure.
        try outsideMarkerContents.write(to: outsideMarkerURL, atomically: false, encoding: .utf8)
        log("virtiofs: created OUTSIDE-share negative-control file \(outsideMarkerURL.path) (must stay unreachable from the guest at /mnt/share/\(outsideMarkerName))")
    } catch {
        // A parent dir we can't write to (e.g. a --share-dir whose parent
        // isn't ours) means the negative control wasn't planted — the
        // guest's later ENOENT would be unfalsifiable, same failure mode
        // this fix closes. Fail loudly instead of silently degrading to
        // that.
        fail("virtiofs: could not create negative-control file at \(outsideMarkerURL.path): \(error)")
    }

    let sharedDirectory = VZSharedDirectory(url: shareDirURL!, readOnly: false)
    let singleShare = VZSingleDirectoryShare(directory: sharedDirectory)
    let fsConfig = VZVirtioFileSystemDeviceConfiguration(tag: args.shareTag)
    do {
        try VZVirtioFileSystemDeviceConfiguration.validateTag(args.shareTag)
    } catch {
        fail("virtiofs tag '\(args.shareTag)' invalid: \(error)")
    }
    fsConfig.share = singleShare
    config.directorySharingDevices = [fsConfig]
    log("virtiofs: sharing \(dirPath) as tag '\(args.shareTag)'")
}

// MARK: - vsock control channel

var vsockDeviceConfig: VZVirtioSocketDeviceConfiguration? = nil
if args.enableVsock {
    let vsockConfig = VZVirtioSocketDeviceConfiguration()
    config.socketDevices = [vsockConfig]
    vsockDeviceConfig = vsockConfig
    log("vsock: device configured, will listen on guest-dialed port \(args.vsockPort) once VM starts")
}

do {
    try config.validate()
} catch {
    fail("configuration invalid: \(error)")
}

log("kernel:  \(args.kernelPath)")
log("initrd:  \(args.initrdPath ?? "none")")
log("cmdline: \(args.cmdLine)")
log("memory:  \(args.memoryMiB) MiB, cpus: \(args.cpuCount)")
log("starting VM, will run for up to \(args.timeoutSeconds)s ...")
log("---- guest console output follows ----")

final class Delegate: NSObject, VZVirtualMachineDelegate {
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        log("guest requested stop")
        finish(code: 0)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        log("VM stopped with error: \(error)")
        finish(code: 1)
    }
}

// Accepts the guest-initiated vsock connection dialed by guest-init
// (VMADDR_CID_HOST, args.vsockPort — see guest-init/src/main.rs).
//
// AAASM-5837: when `args.controlSocketPath` is set, this stops replying with
// the fixed greeting and instead becomes a dumb bidirectional byte pump
// between the guest vsock connection and a Unix-domain socket at that path.
// This process never parses a single byte that crosses the pump — the wire
// protocol (`aa-isolation-vm-proto`) is Rust code shared between the host
// (`aa-isolation-macos-vm`) and guest (`guest-init`) processes, and keeping
// Swift ignorant of it means a protocol change never touches this file or
// requires re-signing/re-verifying the entitled helper binary. Rust is
// expected to already be listening on `controlSocketPath` before the VM
// boots — `accept()` returning there *is* the "guest is connected" signal,
// which is why this class does not itself send anything on connect.
//
// Falls back to the AAASM-5812 fixed hello/reply when no control socket is
// configured, preserving that behaviour for the boot-proof and virtiofs/vsock
// passes' own existing verification commands.
final class VsockListenerDelegate: NSObject, VZVirtioSocketListenerDelegate {
    var connectionAccepted = false
    var roundTripSucceeded = false
    // Set once either side of the pump reaches EOF. Polled by a watcher
    // declared after `vm`/`finish` exist (this class is defined before
    // those top-level values, so it cannot call them directly) — see the
    // watcher below the VM setup, which mirrors the existing boot-marker
    // watcher's own polling pattern.
    var pumpEnded = false
    private let controlSocketPath: String?
    private var activeHandle: FileHandle?
    // VZVirtioSocketConnection owns the fd `activeHandle` wraps — without
    // keeping the connection itself alive here, it was observed to be
    // deallocated (closing the fd out from under the FileHandle) before the
    // readabilityHandler ran, crashing with NSFileHandleOperationException
    // "Bad file descriptor" on `fh.availableData`.
    private var activeConnection: VZVirtioSocketConnection?
    // Same reasoning as activeConnection/activeHandle above, for the
    // control-socket side of the pump.
    private var controlHandle: FileHandle?

    init(controlSocketPath: String?) {
        self.controlSocketPath = controlSocketPath
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        connectionAccepted = true
        log("vsock: incoming connection accepted, guest sourcePort=\(connection.sourcePort)")
        activeConnection = connection
        let vsockHandle = FileHandle(fileDescriptor: connection.fileDescriptor, closeOnDealloc: false)
        activeHandle = vsockHandle

        guard let controlSocketPath else {
            vsockHandle.readabilityHandler = { [weak self] fh in
                let data = fh.availableData
                guard !data.isEmpty else { return }
                let text = String(data: data, encoding: .utf8) ?? "<non-utf8 \(data.count) bytes>"
                log("vsock: received from guest: \(text.trimmingCharacters(in: .whitespacesAndNewlines))")
                fh.write("hello-from-host-vsock\n".data(using: .utf8)!)
                log("vsock: reply sent to guest")
                self?.roundTripSucceeded = true
                fh.readabilityHandler = nil
            }
            return true
        }

        let controlFd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard controlFd >= 0 else {
            log("control-socket: socket() failed errno=\(errno)")
            return false
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(controlSocketPath.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            log("control-socket: path too long: \(controlSocketPath)")
            close(controlFd)
            return false
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { rawPtr in
            let buf = rawPtr.bindMemory(to: CChar.self)
            for (i, byte) in pathBytes.enumerated() {
                buf[i] = CChar(bitPattern: byte)
            }
            buf[pathBytes.count] = 0
        }
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(controlFd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            log("control-socket: connect(\(controlSocketPath)) failed errno=\(errno)")
            close(controlFd)
            return false
        }
        log("control-socket: connected to \(controlSocketPath), pumping bytes")

        let ctrlHandle = FileHandle(fileDescriptor: controlFd, closeOnDealloc: true)
        controlHandle = ctrlHandle

        // Guest → control socket.
        vsockHandle.readabilityHandler = { [weak self] fh in
            let data = fh.availableData
            if data.isEmpty {
                // EOF from the guest: stop pumping in both directions and
                // let the control socket's own EOF (below) tell the Rust
                // side the connection ended.
                self?.controlHandle?.closeFile()
                fh.readabilityHandler = nil
                self?.pumpEnded = true
                return
            }
            self?.roundTripSucceeded = true
            self?.controlHandle?.write(data)
        }
        // Control socket → guest.
        ctrlHandle.readabilityHandler = { [weak self] fh in
            let data = fh.availableData
            if data.isEmpty {
                self?.activeHandle?.closeFile()
                fh.readabilityHandler = nil
                self?.pumpEnded = true
                return
            }
            self?.activeHandle?.write(data)
        }
        return true
    }
}
let vsockListenerDelegate = VsockListenerDelegate(controlSocketPath: args.controlSocketPath)

let vm = VZVirtualMachine(configuration: config)
let delegate = Delegate()
vm.delegate = delegate

var finished = false
func finish(code: Int32) {
    guard !finished else { return }
    finished = true
    consolePipe.fileHandleForReading.readabilityHandler = nil
    log("---- end guest console output ----")
    if args.enableVsock {
        log("vsock: connectionAccepted=\(vsockListenerDelegate.connectionAccepted) roundTripSucceeded=\(vsockListenerDelegate.roundTripSucceeded)")
    }
    writeEvidence()
    exit(code)
}

func writeEvidence() {
    captureLock.lock()
    let data = capturedOutput
    captureLock.unlock()
    let evidencePath = ProcessInfo.processInfo.environment["POC_EVIDENCE_PATH"] ?? "boot-console.log"
    do {
        try data.write(to: URL(fileURLWithPath: evidencePath))
        log("full console capture written to \(evidencePath) (\(data.count) bytes)")
    } catch {
        log("could not write evidence file: \(error)")
    }
}

vm.start { result in
    switch result {
    case .success:
        log("VZVirtualMachine.start succeeded, state=\(vm.state.rawValue)")
        if args.enableVsock, let socketDevice = vm.socketDevices.first as? VZVirtioSocketDevice {
            let listener = VZVirtioSocketListener()
            listener.delegate = vsockListenerDelegate
            socketDevice.setSocketListener(listener, forPort: args.vsockPort)
            log("vsock: host listener registered on port \(args.vsockPort)")
        }
    case .failure(let error):
        fail("VZVirtualMachine.start failed: \(error)")
    }
}

// Boot-marker watcher: if the caller supplied one, poll the captured output
// and stop the VM as soon as it appears instead of waiting for the full
// timeout.
if let marker = args.bootMarker {
    let markerData = marker.data(using: .utf8)!
    DispatchQueue.global().async {
        while !finished {
            captureLock.lock()
            let found = capturedOutput.range(of: markerData) != nil
            captureLock.unlock()
            if found {
                log("boot marker '\(marker)' observed in console output")
                DispatchQueue.main.async {
                    vm.stop { _ in finish(code: 0) }
                }
                return
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
    }
}

// AAASM-5837: when a control socket is configured, either side of the pump
// reaching EOF means this launch's protocol exchange has ended — stop the VM
// rather than waiting on a timeout that may not even be armed (see
// `--timeout 0` below). Mirrors the boot-marker watcher's own polling
// pattern for the same forward-reference reason (VsockListenerDelegate is
// defined before `vm`/`finish` exist).
if args.controlSocketPath != nil {
    DispatchQueue.global().async {
        while !finished {
            if vsockListenerDelegate.pumpEnded {
                log("control-socket: pump ended, stopping VM")
                DispatchQueue.main.async {
                    if vm.canStop {
                        vm.stop { _ in finish(code: 0) }
                    } else {
                        finish(code: 0)
                    }
                }
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }
}

// Bounded run: always stop after the timeout even if no marker fires.
// AAASM-5837: `--timeout 0` means no deadline — a supervised launch's
// lifetime is owned by the Rust process on the other end of
// `--control-socket`, not by a fixed wall-clock bound. Rust closing that
// socket produces EOF on the guest vsock's read side (see
// VsockListenerDelegate above), which is this process's actual signal to
// stop; there is nothing for a timer to add in that mode except a spurious
// kill of a launch that is legitimately still running.
if args.timeoutSeconds > 0 {
    DispatchQueue.main.asyncAfter(deadline: .now() + args.timeoutSeconds) {
        guard !finished else { return }
        log("timeout reached (\(args.timeoutSeconds)s), stopping VM")
        if vm.canStop {
            vm.stop { error in
                if let error {
                    log("stop error: \(error)")
                }
                finish(code: 0)
            }
        } else {
            finish(code: 0)
        }
    }
}

RunLoop.main.run()
