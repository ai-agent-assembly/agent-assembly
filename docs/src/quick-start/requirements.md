# Requirements

Before you install Agent Assembly, make sure your machine meets the
prerequisites below. The CLI and the governing gateway run on macOS and Linux;
only the kernel-level eBPF mechanism is Linux-only.

## At a glance

| You want to… | You need |
|---|---|
| Install and run the `aasm` CLI from a release | A supported OS (macOS or Linux) — nothing else |
| Build the workspace from source | Rust stable ≥ 1.75, `protoc`, and a C toolchain |
| Run the SDK or sidecar-proxy mechanisms | macOS **or** Linux |
| Run the eBPF mechanism | **Linux only** — a recent kernel with BTF and a nightly Rust toolchain |

## Supported platforms

The three enforcement mechanisms have different platform reach. The SDK shim
and the sidecar proxy (`aa-proxy`) run anywhere the runtime builds; the
kernel-level eBPF mechanism is Linux-only.

| Platform | Runtime / CLI | Sidecar proxy (`aa-proxy`) | eBPF |
|---|---|---|---|
| Linux (x86_64 / arm64) | ✅ | ✅ | ✅ — kernel with BTF + nightly toolchain |
| macOS (Apple Silicon / Intel) | ✅ | ✅ | ❌ — Linux-only |
| Windows | ⚠️ via WSL2 | ⚠️ via WSL2 | ⚠️ via WSL2 |

On macOS, governance runs through the **SDK** and **proxy** mechanisms; eBPF
is unavailable. See [`aa-ebpf/README.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/aa-ebpf/README.md)
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

## Requirements per enforcement mechanism

Each mechanism can be deployed independently. Pick the mechanisms you need and
install only their requirements.

| Mechanism | What it does | Requirements |
|---|---|---|
| **SDK shim** (in-process) | Fastest path; the agent adopts a language SDK that reports to the gateway | The relevant SDK: [python-sdk](https://github.com/ai-agent-assembly/python-sdk), [node-sdk](https://github.com/ai-agent-assembly/node-sdk), or [go-sdk](https://github.com/ai-agent-assembly/go-sdk). Runs on macOS or Linux. |
| **Sidecar proxy** (`aa-proxy`) | Intercepts routed outbound HTTP/1.1 via MitM, using per-host certificates minted from a local root CA. No *agent code* change, but the process must honour `HTTP_PROXY`/`HTTPS_PROXY` and trust the CA | macOS or Linux; Windows unsupported. On Linux, `pkg-config` + `libssl-dev`/`openssl-devel`, and CA trust is an explicit `sudo aasm proxy install-ca`. On macOS the install is *attempted* at proxy start via `security add-trusted-cert`, which requires admin authorization — macOS prompts, and a refusal fails proxy startup. |
| **eBPF** (kernel) | Observes OpenSSL TLS plaintext plus `exec`/file syscalls — reports, does not block. TLS uprobes and exec tracepoints work on x86_64 and aarch64; the **file-I/O kprobes are x86_64-only** (hardcoded `__x64_sys_*`) | **Linux only.** A recent kernel with BTF enabled and a nightly Rust toolchain to build the BPF-target crates. Not available on macOS. |

> **The eBPF caveat.** The `aa-ebpf-probes` and `aa-ebpf-programs` crates compile
> for the `bpfel-unknown-none` target and are intentionally outside the host
> Cargo workspace. They cannot be selected with `cargo -p` and do not build on
> macOS. If you are on macOS, you can still run and govern agents through the SDK
> and proxy mechanisms — you simply do not get the kernel-level mechanism.

## Execution isolation (`aasm run --isolation`)

This is a separate capability from the three enforcement mechanisms above, and
has its own, narrower platform reach: **Linux only**, and even there it
requires a backend executable Agent Assembly does not bundle.

| Platform | `aasm run --isolation process`/`auto` | Requirement |
|---|---|---|
| Linux | ✅ | A separately-installed backend executable on `PATH` (or `AA_SANDLOCK_BIN`) |
| macOS | ❌ Refused, never silently unconfined | No backend targets macOS |
| Windows | ❌ Refused, never silently unconfined | No backend targets Windows |

See [Execution isolation](../security/execution-isolation.md#platform-and-backend-support-matrix)
for the full support matrix, the runtime prerequisites, and what to expect
when the backend is absent.

## Next

With the prerequisites in place, continue to [Installation](installation.md).
