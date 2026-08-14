# Platform-specific host adapters

This page is for anyone deciding whether host-level enforcement is available on
their target platform, and what it actually does there. It is a reader-facing
distillation of [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md)
§4–5.3, which remains the source of truth and carries the full code citations —
start here for orientation, go there for the evidence trail.

## The contract: E4 is a role, not a product

ADR 0033 names **E4 — Platform-Specific Host-Level Interception Adapters** as an
*architectural role*: OS-level mediation of processes, files, syscalls and TLS,
sitting alongside (not below or after) the other five elements — the control
plane, managed execution checkpoints, transport mediation, the credential
boundary, and the evidence pipeline. Each platform needs its own mechanism, and
a platform without one simply has none — absence is a reportable state, never a
silent fall-through to another element.

**eBPF is not an architectural layer. It is one implementation of E4, available
on Linux.** Nothing else in this product's design assumes eBPF, and no other
platform inherits eBPF's behaviour by proximity.

## Linux — the only platform with an E4 implementation today

Linux eBPF, via the privileged `aa-ebpf-loaderd` daemon, is reachable only when
**all** of the following hold: kernel ≥ 5.8, BTF available at
`/sys/kernel/btf/vmlinux`, and a reachable loader socket
(`fn probe_ebpf`, `aa-runtime/src/layer.rs:133-135`). `bpf_send_signal`
additionally needs kernel ≥ 5.3. `aa-runtime` itself holds no `CAP_BPF` — the
loader daemon is the sole capability holder, a deliberate privilege separation.

### What each program does

| Program | Attach point | Behaviour |
| --- | --- | --- |
| SSL uprobes (`ssl_write`, `ssl_read_entry`, `ssl_read_exit`) | uprobes/uretprobe on OpenSSL | **Observe only** — logged, not bridged into the audit pipeline |
| File-I/O kprobes (14 targets) | `__x64_sys_*` — **x86_64-only**, no `__arm64_sys_*` target exists | **Observe only** — a path-blocklist hit sets an alert bit; the syscall proceeds |
| Exec tracepoints | `sched_process_{fork,exec,exit}` | **Observe only**; no ring-buffer reader is wired yet |
| **Syscall guard** | `raw_syscalls/sys_enter` + fork/exit | The **only enforcing program** — default-denies syscalls outside the allowlist via `bpf_send_signal(SIGKILL)` |

### The syscall guard's four properties, every time it is mentioned

1. **Not a synchronous deny.** The offending syscall executes once before the
   task dies. A true synchronous deny needs seccomp-BPF or a `bpf_lsm` hook;
   neither exists in the tree.
2. **Off by default.** It activates only when `AA_EBPF_CONFINE_PID` names a PID
   *and* policy lowering yields a non-empty allowlist.
3. **Has a documented load-time race.** A window exists between guard load and
   allowlist update in which the confined PID runs with an empty allowlist.
4. **Cannot block a fork** — an acknowledged fail-open.

**No eBPF signal participates in any allow/deny decision.** `aa-gateway` has no
direct dependency on `aa-ebpf`; events terminate in the audit publisher and the
correlation engine. The only reverse link is policy lowering pushing a syscall
allowlist into the opt-in guard.

### Known exclusions

- File-I/O kprobes: **x86_64 only** — Linux aarch64 gets no file-I/O coverage
  from this mechanism.
- SSL/exec observation events are not yet bridged to the durable audit pipeline.
- The syscall guard is the sole enforcement point, is opt-in, and fails open on
  fork.

## macOS — no E4 adapter, but not "no host enforcement"

**Status: Unsupported (E4).** Endpoint Security and Network Extension are an
explicit, documented non-goal — this is a product decision, not a gap someone
forgot to fill, and it is pinned by a test asserting the literal limitation
string.

That said, **do not read "no E4 adapter" as "no host enforcement on macOS."**
macOS is the *only* platform where ADR 0030's `HostEnforced` protection state is
reachable in production today, via an entirely different route: an opt-in,
privileged, authorized managed-settings file write (the Claude Code integration's
`EvidenceKind::HostAttested` path). Two things to hold in mind about that route:

- It is a **root-owned managed-settings file write** — outside the two routes
  ADR 0030 §4.1 names, which is why ADR 0033 amends ADR 0030 rather than merely
  complementing it.
- Whether the target tool actually **honours** those keys at runtime is
  **unmeasured** — the adapter's own documentation calls this "the open half" of
  its enabling ticket. The reachable state rests on a read-back of the file that
  was written, not on observed enforcement.

`aa-proxy` (E3, transport mediation) is separately available on macOS — a System
Keychain trust install is attempted automatically at proxy start when the
certificate is not already installed, and requires an admin authorization
prompt; a refused prompt fails proxy startup. DTrace was considered and rejected
during the original design as observability-only, not enforcement; no DTrace
code exists in the tree.

## Windows — unsupported, both E3 and E4

**Status: Unsupported.** `aa-proxy`'s accept loop depends on `tokio::signal::unix`
unconditionally, so the crate has no Windows build path at all — E3 is also
absent, not just E4. `#[cfg(windows)]` blocks exist in a few places, but
`windows_sys` is declared in no `Cargo.toml` in the workspace, so those blocks
cannot compile as written. No ETW, WFP or minifilter code exists for E4.

## Status labels, stated plainly

| Platform | E3 (transport mediation) | E4 (host-level interception) |
| --- | --- | --- |
| Linux x86_64 | Implemented | Implemented, with the limits above |
| Linux aarch64 | Implemented | Implemented (partial) — no file-I/O kprobes |
| macOS | Implemented | Unsupported — see the `HostEnforced` exception above |
| Windows | Unsupported | Unsupported |

Any future macOS or Windows host adapter is **research** until an
implementation exists in the tree, and must be labelled as research or planned —
never described as available on the strength of a conceptual API (Endpoint
Security, Network Extension, ETW, WFP) that this product does not call.

## How E4 relates to the other elements

- **E2 (managed execution checkpoints)** and **E3 (transport mediation)** are
  reachable independent of E4 — an agent that never triggers a host-level probe
  can still be governed at the checkpoint or the wire.
- **E5 (credential/capability boundary)** and **E1 (control plane)** are
  platform-independent; nothing about them changes based on E4's availability.
- **E6 (evidence & protection-state pipeline)** is what reports E4's absence or
  degradation — a missing E4 adapter is a state E6 records, not a silent
  fall-through to another element picking up the slack.

## Related and coordinating work

- [ADR 0033](../adr/0033-canonical-governance-and-enforcement-architecture.md) —
  full decision record, code citations, and the claim vocabulary (§6) this page's
  status words are drawn from.
- [ADR 0030](../adr/0030-developer-integration-boundaries-and-trust-model.md) — the
  `HostEnforced` protection-state ladder the macOS exception above refers to.
- [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534) —
  cross-platform host-wide mediation research; any macOS/Windows E4 adapter that
  ships starts here.
- [AAASM-5535](https://lightning-dust-mite.atlassian.net/browse/AAASM-5535) —
  protection states this page's macOS exception depends on.
