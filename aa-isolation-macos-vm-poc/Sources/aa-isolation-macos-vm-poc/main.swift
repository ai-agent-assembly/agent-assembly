// AAASM-5812 PoC — prove Virtualization.framework can boot a Linux kernel
// on this host with real console output reaching the host process.
//
// Deliberately narrow scope: no virtiofs, no vsock, no NAT networking, no
// aa-isolation-launch guest cross-compile. See README.md for what this
// proves and what it does not.

import Foundation
import Virtualization

// MARK: - CLI arguments

struct Args {
    var kernelPath: String
    var initrdPath: String
    var cmdLine: String
    var memoryMiB: UInt64
    var cpuCount: Int
    var timeoutSeconds: Double
    var bootMarker: String?
}

func parseArgs() -> Args {
    var kernelPath = "images/vmlinuz-virt"
    var initrdPath = "images/initramfs-virt"
    var cmdLine = "console=hvc0"
    var memoryMiB: UInt64 = 768
    var cpuCount = 2
    var timeoutSeconds = 45.0
    var bootMarker: String? = nil

    var args = CommandLine.arguments.dropFirst().makeIterator()
    while let arg = args.next() {
        switch arg {
        case "--kernel":
            kernelPath = args.next() ?? kernelPath
        case "--initrd":
            initrdPath = args.next() ?? initrdPath
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
        default:
            FileHandle.standardError.write("unknown argument: \(arg)\n".data(using: .utf8)!)
        }
    }

    return Args(
        kernelPath: kernelPath,
        initrdPath: initrdPath,
        cmdLine: cmdLine,
        memoryMiB: memoryMiB,
        cpuCount: cpuCount,
        timeoutSeconds: timeoutSeconds,
        bootMarker: bootMarker
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
guard FileManager.default.fileExists(atPath: args.initrdPath) else {
    fail("initrd not found at \(args.initrdPath) — run scripts/fetch-images.sh first")
}

let kernelURL = URL(fileURLWithPath: args.kernelPath)
let initrdURL = URL(fileURLWithPath: args.initrdPath)

let bootLoader = VZLinuxBootLoader(kernelURL: kernelURL)
bootLoader.initialRamdiskURL = initrdURL
bootLoader.commandLine = args.cmdLine

let config = VZVirtualMachineConfiguration()
config.bootLoader = bootLoader
config.cpuCount = args.cpuCount
config.memorySize = args.memoryMiB * 1024 * 1024

let serialConfig = VZVirtioConsoleDeviceSerialPortConfiguration()
let serialAttachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: nil,
    fileHandleForWriting: consolePipe.fileHandleForWriting
)
serialConfig.attachment = serialAttachment
config.serialPorts = [serialConfig]

// No network, no storage, no virtiofs, no vsock devices — deliberately out
// of scope for this pass (see README).
config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

do {
    try config.validate()
} catch {
    fail("configuration invalid: \(error)")
}

log("kernel:  \(args.kernelPath)")
log("initrd:  \(args.initrdPath)")
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

let vm = VZVirtualMachine(configuration: config)
let delegate = Delegate()
vm.delegate = delegate

var finished = false
func finish(code: Int32) {
    guard !finished else { return }
    finished = true
    consolePipe.fileHandleForReading.readabilityHandler = nil
    log("---- end guest console output ----")
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

// Bounded run: always stop after the timeout even if no marker fires.
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

RunLoop.main.run()
