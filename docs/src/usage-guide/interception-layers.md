# Choosing interception layers

**Goal.** Decide which of the three interception layers to deploy, and how to
combine them, for a given governance requirement. Agent Assembly enforces policy
through three independently-deployable layers; this page is about the practical
trade-offs, with the real commands for each.

## The three layers at a glance

Listed lowest-latency-cost first, highest-detection-authority first:

| Layer | What it is | Catches | Cost / requirement |
|---|---|---|---|
| **1. SDK (in-process)** | A thin Rust shim (`aa-ffi-*` over `aa-sdk-client`) the language SDKs call. Emits events to the gateway and applies pre-execution allow/deny via wrapper functions. | Framework tool calls that are wrapped, after the SDK's initializer is called. Raw HTTP, subprocess spawns and file access are not intercepted. | Lowest latency, but requires the agent to adopt the SDK. |
| **2. Proxy sidecar (`aa-proxy`)** | Intercepts routed outbound HTTP/1.1 via MitM, using per-host certificates minted from a local root CA. Enforces network-egress policy with no *agent code* change. | Network traffic the SDK misses **that is routed to it** on a host under MitM. | No agent code change, but the process must honour the proxy environment and trust the CA; HTTP/2, gRPC and WebSocket are out of scope. |
| **3. eBPF (`aa-ebpf*`)** | Kernel hooks: uprobes on OpenSSL, kprobes/tracepoints on `exec`/file syscalls. | OpenSSL TLS plaintext and process/file activity the layers above never saw — **observed, not blocked**. | Highest *detection* authority; **Linux only** (file-I/O kprobes x86_64-only), needs the privileged loader daemon, and fails open if it cannot attach. |

The gateway is the common brain for all three — every layer asks the same policy
engine for its decision and writes to the same audit log.

## When to use each

- **Reach for the SDK layer** when you control the agent's code and want the
  lowest-overhead, most precise instrumentation — it sees tool-call arguments
  and results directly, in process.
- **Add the proxy** when you cannot or do not want to modify the agent, and the
  risk you care about is network egress / data exfiltration. It is the most
  practical way to govern a third-party or closed-source tool. See
  [Enforce an egress policy](enforce-egress-policy.md).
- **Add eBPF** when you need visibility into what an agent does outside the paths
  the other layers cover — e.g. it shells out, writes files, or makes raw
  connections that skip both the SDK and the proxy. It raises the chance of
  *detecting* such a bypass; it is a detection backstop, not a catch-all, and it
  does not block.

## Combining layers

The layers are additive, not exclusive. A typical governed deployment runs the
SDK *and* the proxy: the SDK gives rich, in-process tool-call governance, while
the proxy backstops the network path for anything the SDK does not see and that
is routed through it. On Linux, eBPF sits underneath both as an
observation floor — it widens what you can detect, not what you can prevent.

For what remains uncovered even with all three deployed, see [Limitations and
known bypasses](../devtools/limitations.md).

`aasm run` reports a **governance level** per tool (see
[Govern an agent end-to-end](govern-an-agent.md)), but read it for what it is: a
static, self-declared *ceiling* on how deeply an adapter could integrate — no
in-tree adapter declares `L3Native` today, and every local dev-tool adapter
declares `L2Enforce`. It is not a measurement and not a protection claim.

For what is actually protecting a given tool right now, and the evidence behind
it, use [`aasm integrations status <tool>`](../cli/integrations.md), which
reports the derived [protection ladder](../devtools/protection-levels.md).
(`aasm run` and `aasm integrations` are stripped from the crates.io publish
only — a source build, the GitHub Release tarballs, the `curl` installer and
the Homebrew formula all carry them.)

## Layer 2 in practice — the proxy

```console
$ sudo aasm proxy install-ca # trust the local root CA so TLS interception works
$ aasm proxy start           # background sidecar on 127.0.0.1:8899
$ aasm proxy status          # confirm it is running
$ aasm proxy logs            # tail the proxy log
$ aasm proxy uninstall-ca    # remove the CA when you are done
```

`aasm proxy start` takes `--listen <addr>` (default `127.0.0.1:8899`),
`--gateway <url>`, and `--ca-dir <dir>`.

## Layer 3 in practice — eBPF

The eBPF layer is **Linux-only**: its uprobes/kprobes/tracepoints attach to a
running kernel.

```console
$ aasm proxy status
not running
```

On macOS the eBPF userspace crate compiles with non-Linux stubs (the
`KprobeManager`/`UprobeManager` attach paths are `#[cfg(target_os = "linux")]`),
so it builds for development but does not attach probes. To exercise the real
kernel hooks — SSL-library uprobes for outbound TLS, `exec`/`openat`/`unlink`
kprobes, and the `sched_process_exec` tracepoint — run on Linux.

> **Honest caveat.** This page does not show live eBPF probe output because the
> attaching code is gated to Linux and this build was exercised on macOS. The
> architecture (userspace `aa-ebpf` loading compiled `aa-ebpf-probes` and reading
> a shared BPF ring buffer) is real and documented in the crate; the live capture
> requires a Linux host with the privileges to load eBPF programs.

## Result

You can match the interception layer (or stack of layers) to the requirement:
SDK for precision where you own the code, proxy for egress control without
touching agent code, eBPF for kernel-level *detection* of what escaped both on
Linux — all feeding one gateway and one audit log.

Match the requirement to what the layer can promise, too: the SDK and the proxy
can deny an action before it runs; eBPF tells you an action happened.
