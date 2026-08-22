// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "aa-isolation-macos-vm-poc",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "aa-isolation-macos-vm-poc",
            path: "Sources/aa-isolation-macos-vm-poc"
        )
    ]
)
