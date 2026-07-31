# Choosing interception layers

**Goal.** Decide which of the three interception layers to deploy, and how to
combine them, for a given governance requirement. Agent Assembly enforces policy
through three independently-deployable layers; this page is about the practical
trade-offs, with the real commands for each.

## The three layers at a glance

Listed lowest-latency-cost first, highest-detection-authority first:

| Layer | What it is | Catches | Cost / requirement |
|---|---|---|---|
| **1. SDK (in-process)** | A thin Rust shim (`aa-ffi-*` over `aa-sdk-client`) the language SDKs call. Emits events to the gateway and applies pre-execution allow/deny via wrapper functions. | Anything the instrumented code path does. | Lowest latency, but requires the agent to adopt the SDK. |
| **2. Proxy sidecar (`aa-proxy`)** | Intercepts outbound HTTPS via MitM with a per-host CA. Enforces network-egress policy with no code change. | Anything the SDK misses that goes over the network. | No code change; requires trusting the proxy CA. |
| **3. eBPF (`aa-ebpf*`)** | Kernel hooks: uprobes on SSL libraries, kprobes/tracepoints on `exec`/file syscalls. | Everything else, including deliberate bypass attempts. | Highest authority; **Linux-only**. |

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
- **Add eBPF** when you need defense-in-depth that an agent cannot bypass — e.g.
  it shells out, writes files, or makes raw connections that skip both the SDK
  and the proxy. This is the catch-all backstop.

## Combining layers

The layers are additive, not exclusive. A typical governed deployment runs the
SDK *and* the proxy: the SDK gives rich, in-process tool-call governance, while
the proxy backstops the network path for anything the SDK does not see. On Linux,
eBPF sits underneath both as the bypass-proof floor.

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
$ aasm proxy install-ca      # trust the per-host CA so TLS interception works
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
SDK for precision where you own the code, proxy for code-free egress control,
eBPF for a bypass-proof kernel backstop on Linux — all feeding one gateway and
one audit log.
