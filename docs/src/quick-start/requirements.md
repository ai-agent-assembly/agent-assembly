# Requirements

Before you install Agent Assembly, make sure your machine meets the
prerequisites below. The CLI and the governing gateway run on macOS and Linux;
only the kernel-level eBPF interception layer is Linux-only.

## At a glance

| You want to… | You need |
|---|---|
| Install and run the `aasm` CLI from a release | A supported OS (macOS or Linux) — nothing else |
| Build the workspace from source | Rust stable ≥ 1.75, `protoc`, and a C toolchain |
| Run the SDK or sidecar-proxy interception layers | macOS **or** Linux |
| Run the eBPF interception layer | **Linux only** — a recent kernel with BTF and a nightly Rust toolchain |

## Supported platforms

The three interception layers have different platform reach. The SDK shim and
the sidecar proxy (`aa-proxy`) run anywhere the runtime builds; kernel-level
eBPF interception is Linux-only.

| Platform | Runtime / CLI | Sidecar proxy (`aa-proxy`) | eBPF interception |
|---|---|---|---|
| Linux (x86_64 / arm64) | ✅ | ✅ | ✅ — kernel with BTF + nightly toolchain |
| macOS (Apple Silicon / Intel) | ✅ | ✅ | ❌ — Linux-only |
| Windows | ⚠️ via WSL2 | ⚠️ via WSL2 | ⚠️ via WSL2 |

On macOS, governance is enforced through the **SDK** and **proxy** layers; the
eBPF layer is unavailable. See [`aa-ebpf/README.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/aa-ebpf/README.md)
for kernel requirements.

## Installing the CLI only

If you just want the `aasm` operator CLI from a published release, you need
nothing more than a supported OS. The [quick-install script](installation.md)
downloads a pre-built binary for `x86_64`/`aarch64` on macOS
(`apple-darwin`) and Linux (`unknown-linux-gnu`). Jump straight to
[Installation](installation.md).

## Building from source

To build the Cargo workspace yourself — for development, or to run the gateway
via `cargo run` — install the following.

### Required

- **Rust stable, ≥ 1.75** — install via [rustup](https://rustup.rs/). The
  workspace uses the 2021 edition.
- **`protoc`** — the Protocol Buffers compiler, required by the `aa-proto` and
  `aa-gateway` build scripts.
  - macOS: `brew install protobuf`
  - Debian / Ubuntu: `apt-get install protobuf-compiler`

### Recommended developer tooling

These are not needed to *run* the CLI but are used by the test and contribution
workflow:

- [`cargo-nextest`](https://nexte.st/) — the test runner used across the workspace.
- [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) — dependency and
  license checks.
- [Lefthook](https://github.com/evilmartians/lefthook) — git pre-commit / pre-push hooks.

### Linux-only build dependencies

On Linux, the native-TLS path in `aa-proxy` additionally requires:

- `pkg-config`
- `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (RHEL-family)

## Requirements per interception layer

Each interception layer can be deployed independently. Pick the layers you need
and install only their requirements.

| Layer | What it does | Requirements |
|---|---|---|
| **SDK shim** (in-process) | Fastest path; the agent adopts a language SDK that reports to the gateway | The relevant SDK: [python-sdk](https://github.com/ai-agent-assembly/python-sdk), [node-sdk](https://github.com/ai-agent-assembly/node-sdk), or [go-sdk](https://github.com/ai-agent-assembly/go-sdk). Runs on macOS or Linux. |
| **Sidecar proxy** (`aa-proxy`) | Intercepts outbound HTTPS via MitM with a per-host CA — no code changes | macOS or Linux. On Linux, `pkg-config` + `libssl-dev`/`openssl-devel`. |
| **eBPF** (kernel) | Catches everything else, including bypass attempts | **Linux only.** A recent kernel with BTF enabled and a nightly Rust toolchain to build the BPF-target crates. Not available on macOS. |

> **The eBPF caveat.** The `aa-ebpf-probes` and `aa-ebpf-programs` crates compile
> for the `bpfel-unknown-none` target and are intentionally outside the host
> Cargo workspace. They cannot be selected with `cargo -p` and do not build on
> macOS. If you are on macOS, you can still run and govern agents through the SDK
> and proxy layers — you simply do not get the kernel-level layer.

## Next

With the prerequisites in place, continue to [Installation](installation.md).
