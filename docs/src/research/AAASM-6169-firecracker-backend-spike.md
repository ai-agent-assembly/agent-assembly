# AAASM-6169 — Firecracker microVM backend spike (Spike report)

**Ticket**: [AAASM-6169](https://lightning-dust-mite.atlassian.net/browse/AAASM-6169)
**Epic**: [AAASM-6159](https://lightning-dust-mite.atlassian.net/browse/AAASM-6159) — Agent Execution Runtime 2.0
**Consumed by**: [AAASM-6167](https://lightning-dust-mite.atlassian.net/browse/AAASM-6167) — evidence-aware runtime classes / property-based backend selection
**Related**: [AAASM-6162](https://lightning-dust-mite.atlassian.net/browse/AAASM-6162) (transactional COW workspaces), [AAASM-6163](https://lightning-dust-mite.atlassian.net/browse/AAASM-6163) (egress broker), [AAASM-5849](https://lightning-dust-mite.atlassian.net/browse/AAASM-5849)/[AAASM-5869](https://lightning-dust-mite.atlassian.net/browse/AAASM-5869)/[AAASM-5870](https://lightning-dust-mite.atlassian.net/browse/AAASM-5870) (existing macOS VM backend), [ADR 0035](../adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md)
**Surveyed against**: branch `v0.0.1/AAASM-6169/docs/firecracker_backend_spike` @ `77cbbc8db`
**Date**: 2026-09-24
**Prototype**: none. No Linux/KVM host was available in this session (host is macOS/Apple Silicon, which cannot run KVM — Firecracker is Linux/KVM-only, §4.15 below). Per the ticket's own instruction, no hardware evidence is fabricated from an unsupported host. This report is architecture/desk research plus one internal code comparison (the existing macOS VM backend), not a benchmark.

This is a research report. It recommends; it decides nothing. No production behavior,
default, or public contract changes on this branch. Every claim about *this* codebase
carries a `path:line`. Every claim about Firecracker itself is drawn from its publicly
documented architecture (KVM-based, AWS-maintained, used for Lambda/Fargate, minimal
device model, jailer process, snapshot/restore) and is marked **unverified locally** —
this session did not run Firecracker.

---

## 0. Executive summary

Firecracker is a credible **future Linux-host, KVM-available** isolation backend
candidate. It is **not** relevant to this product's current shipping deployment,
which is macOS-hosted and uses Apple's Virtualization.framework (`aa-isolation-macos-vm`,
AAASM-5811/5813/5837) — Firecracker cannot run there directly, and this spike found
no evidence in this codebase that the existing macOS backend configures or relies on
nested virtualization to reach it either (§4.13/4.15).

The one genuinely new thing Firecracker would bring over the existing backend roster
(Sandlock, `aasm-native` Landlock+seccomp, the macOS VM backend) is **snapshot/restore**:
none of the three existing Linux/macOS backends have anything resembling it, and
AAASM-6162's transactional-workspace goal and AAASM-6167's warm-pool interest both
want exactly that primitive. That is the strongest argument for a Linux-hosted
Firecracker backend existing eventually.

Set against that: Firecracker's threat boundary is genuinely stronger than gVisor's
syscall-interception model (hardware-virtualized guest kernel vs. a userspace kernel
sharing the host's syscall surface), but weaker in operational terms than it sounds —
it still requires host KVM access, a jailer/seccomp/cgroup layer that must itself be
configured correctly, and per-microVM kernel+rootfs images this project would have to
build, sign, and patch, on top of everything `aa-isolation-vm-proto`'s guest-toolchain
lesson (AAASM-5849) already cost the macOS VM backend once.

**Verdict, split by deployment context** (§5 below):

- **Current macOS-hosted deployment: NO-GO.** Firecracker requires KVM, which the
  current deployment's host process has no path to. Nothing in this codebase
  configures nested virtualization for the existing macOS VM guest, and this spike
  did not measure whether the underlying platform could support it in principle
  (that is a chip/OS-version question, not a code question — see §4.13).
- **A hypothetical bare-metal/cloud Linux hosted-runtime deployment: CONDITIONAL GO.**
  Worth a real hardware PoC gated on AAASM-6162/6167 actually needing snapshot-backed
  transactional workspaces or warm pools on Linux, and gated on someone measuring
  cold-boot-with-a-real-toolchain latency rather than trusting the 125ms headline
  figure, which is measured against an empty/minimal guest, not this product's
  workload (§4.4).

---

## 1. Existing Decision Summary

Required by `.claude/skills/adr-governance/SKILL.md` Step 4.

```
### Existing Decision Summary
- Applicable ADRs / recorded decisions:
  - ADR 0035 — Agent Execution Isolation & Pluggable Enforcement Backends. The
    governing decision for this whole spike. Decision 2 fixes the IsolationBackend
    contract (capabilities/plan/prepare/spawn/wait_for_exit/terminate/evidence) as
    backend-neutral; decision 3 says isolation class is not backend identity —
    "microVM/hardware-backed" is a stable requirement class, Firecracker (if ever
    shipped) would be one implementor of it, not a CLI-visible name. Decision 11
    requires recorded license/provenance/SBOM before any backend ships. The
    "Alternatives considered" section explicitly named and deferred microVMs
    ("Require a microVM for every launch" — rejected as a universal default,
    reserved as "a future backend class for risk profiles that justify them").
    Reconsideration trigger 3 ("gVisor/userspace-kernel or microVM execution
    becomes a default rather than an optional risk-tier backend") is the trigger
    this spike is scouting toward, not yet firing.
  - AAASM-5801 amendment (native Linux backend) and AAASM-5808 amendment
    (`--isolation auto` capability-walk algorithm) — establish the pattern any
    new backend, Firecracker included, must fit: implement `IsolationBackend`,
    report capabilities truthfully, and let `negotiate()`/`plan()` decide
    eligibility rather than a hand-written comparison.
  - ADR 0033 §6 — canonical claim vocabulary (Denied before execution / Observed
    / Detected / Unsupported / Degraded / Unmeasured / Experimental / Planned).
    Any Firecracker evidence claim must use these terms, not new ones.
  - AAASM-6162 (open, To Do) — transactional COW workspaces; explicitly lists
    "VM/container disk-layer/snapshot mechanisms where appropriate" as a
    candidate backend for its abstraction. This spike's snapshot findings feed
    that ticket's backend survey.
  - AAASM-6167 (open, To Do) — evidence-aware runtime classes; its Goal section
    references "future backend spikes may add candidates" to the property-based
    selector this spike's conclusion is an input to.
- Prior decisions that bear on this change: all of the above. No decision here is
  being reversed, amended, or superseded — this is pure research feeding two open
  tickets (6162, 6167) and confirming a still-dormant ADR 0035 trigger has not yet
  fired.
- Conflicts with what this change would do: none. This branch adds one Markdown
  file (plus a one-line SUMMARY.md index entry) and touches no Rust source, no
  default, and no public contract.
- Missing decisions this change forces: none. It is explicitly a spike, not a
  design; §5 states a verdict but commits nothing.
- Proposed ADR action: **none**. If AAASM-6162 or AAASM-6167 later decide to build
  a Firecracker backend for a Linux hosted-runtime target, that decision belongs
  in a dedicated ADR (most likely an ADR 0035 amendment, following the AAASM-5801/
  5808 pattern), not this spike.
```

---

## 2. What "backend" means in this codebase (survey)

`aa_isolation::IsolationBackend` (`aa-isolation/src/backend.rs:277-381`) is the
contract every implementor — including a hypothetical Firecracker one — must
satisfy: `identity`, `capabilities`, `plan`, `prepare`, `spawn`, `wait_for_exit`,
`terminate`, `evidence`, and the AAASM-5869-added `confined_output` (default `None`,
overridden by backends whose confined process's stdio the supervisor cannot see —
exactly the situation any VM-based backend, Firecracker included, is in).

`PreparedExecution` and `ExecutionHandle` are deliberately opaque tokens
(`backend.rs:40-119`) precisely so a backend whose unit of confinement is not a host
process — a VM, a microVM — has nowhere it needs to leak that shape into the
contract. This means a Firecracker backend needs **no trait change** to exist, the
same conclusion the AAASM-5801 amendment reached for the native Linux backend.

Three backends currently implement it: `aa-isolation-sandlock`, `aa-isolation-native`
(Landlock+seccomp), `aa-isolation-macos-vm` (Apple Virtualization.framework). `--isolation
auto` walks them in a fixed order and picks the first whose `plan()` accepts the spec
(ADR 0035, AAASM-5808 amendment). A Firecracker backend would be a fourth entry in
that same walk, competing on the same `CapabilityDomain` vocabulary
(`aa-isolation/src/capability.rs:43-64`: `FilesystemRead`, `FilesystemWrite`,
`NetworkEgress`, `NameResolution`, `Syscall`, `ProcessCreation`, `Ipc`, `Credential`,
plus resource ceilings) — not a new vocabulary of its own, per ADR 0035 decision 3.

## 3. The existing macOS VM backend — the closest internal comparison

`aa-isolation-macos-vm` (AAASM-5811/5813/5837/5849/5869/5870) is the most relevant
prior art, because it is also VM-based:

- **Mechanism**: Apple Virtualization.framework, driven by a small Swift helper
  process per boot (`aa-isolation-macos-vm/src/lib.rs:1-8`), talking to the
  guest over vsock via a purpose-built protocol (`aa-isolation-vm-proto`).
- **Composition, not a from-scratch sandbox**: the guest runs `aa-isolation-native`
  (Landlock+seccomp) *inside* the VM (`lib.rs:2-4` — "delegating confinement to
  `aa-isolation-native` running inside a Virtualization.framework Linux guest").
  This is nesting on the *guest* side (one confinement mechanism inside the
  guest OS), for a concrete reason (the guest's own OS-level confinement) — it
  is a different question from nesting a second *hypervisor* (KVM/Firecracker)
  inside this VM's guest, which §4.13 addresses directly and which this codebase
  does not attempt anywhere.
- **Startup cost, measured on this host** (`lib.rs:24-29`): "the full round trip
  (boot, connect, launch, exit, teardown) measures at ~0.3s on this host" —
  i.e. ~300ms, in the same order of magnitude as Firecracker's headline ~125ms,
  and for the same class of reason: both are booting a minimal Linux guest, not
  a general-purpose distro. Neither number includes a warm toolchain (below).
- **Guest toolchain gap, found and partially fixed the hard way**: AAASM-5849
  found the guest rootfs shipped only `busybox` — no python/git/node/compiler —
  so `aasm run python script.py` had nothing to exec. The fix (referenced in
  `lib.rs:52-58`) baked `git`, `python3`, and `/bin/sh` into the guest image and
  hard-restricted execution to a fixed allowlist of guest-resident binaries
  (`paths::GUEST_RESIDENT_PROGRAMS`) plus the shared project directory. **This
  is the single most load-bearing internal fact for Firecracker's "startup
  cost" claim below**: a bare microVM boot number is not this product's real
  cost, because a coding-agent workload needs a real toolchain in the guest,
  and building/maintaining that guest image was already a dedicated ticket for
  the *existing* backend, and it is not solved by picking a different VMM.
- **No snapshot/restore of any kind.** `grep -rn "snapshot" aa-isolation-macos-vm/
  aa-isolation-vm-proto/ aa-isolation/` returns **zero matches** (verified this
  pass). The macOS VM backend boots fresh every launch. This is the concrete
  gap Firecracker's headline feature would fill if this product ever needed it
  on Linux — and Virtualization.framework itself does support VM save/restore
  on macOS 14+ (Apple's own `VZVirtualMachine` save-state API), so a macOS-side
  equivalent is a separate, already-available (unused) option worth noting for
  the team pursuing AAASM-6162, independent of whether Firecracker ships
  anywhere.
- **No host-side resource ceiling on the VM process today.** `grep -n
  "cgroup\|rlimit\|memory.*limit" aa-isolation-macos-vm/src/vmm.rs` returns
  **no matches** (verified this pass) — VM guest memory *size* is configured,
  but nothing in this backend enforces a ceiling on the *host* process
  representing the microVM the way a Firecracker jailer's cgroups would
  (§4.9).
- **`grep -n "shared" aa-isolation-macos-vm/src/vmm.rs`** (verified this pass)
  returns only references to the AAASM-5854 shared-rootfs-image *corruption
  fix* (`vmm.rs:184,308,311,359,363,372`) — i.e. "shared" there means "one file
  multiple boots raced on and corrupted, now serialized," not a genuine
  image-sharing-across-concurrent-guests mechanism. There is no shared-image
  optimization to compare Firecracker against; each launch boots its own
  independent guest, on both backends.
- **Known defects worth not repeating**: AAASM-5870 found concurrent
  `VZVirtualMachine.start()` calls intermittently fail directory-sharing
  validation under default test parallelism — a concurrency bug in the *host's*
  VM-start path, not the guest. AAASM-5869 found VM-backed confined stdout/stderr
  requires an explicit `confined_output` override because it arrives over a
  control channel, not inherited stdio — exactly the shape a Firecracker backend
  would also need (Firecracker's own serial console / vsock output is not
  inherited stdio either). Both are evidence that **VM-based backends carry a
  materially different bug class** than process-isolation backends
  (Sandlock/`aasm-native`), independent of which VMM is used.

---

## 4. Firecracker evaluation

Each item below states what is publicly documented about Firecracker (unverified
locally — no KVM host was available), what applies to this codebase, and what
could not be assessed without real infrastructure.

### 4.1 Threat boundary

Firecracker runs each microVM under KVM: the guest executes on virtualized (not
merely namespaced) hardware, with its own kernel, memory space and virtual
devices — a hardware-virtualization boundary, structurally the same class as
Apple's Virtualization.framework already used by `aa-isolation-macos-vm`, and a
different class from gVisor's approach (a userspace kernel intercepting host
syscalls while sharing the host kernel for anything it does not emulate). On top
of the VM boundary, Firecracker adds the **jailer**: a wrapper process that
applies seccomp-bpf filtering, cgroups, and chroot to the Firecracker VMM process
itself, before it ever runs guest code — a second, independent containment layer
around the hypervisor process, not the guest.

Compared internally: this is architecturally closer to `aa-isolation-macos-vm`
(hardware-virtualized guest, host-side process containment for the VMM/helper)
than to `aa-isolation-native` (Landlock+seccomp on the *target* process directly,
no guest kernel at all) or to a hypothetical gVisor backend (userspace kernel,
no guest kernel, no KVM requirement — evaluated separately under the parallel
AAASM-6168 spike, out of scope here). **Unverified locally**: the actual
effectiveness of the jailer's default seccomp policy, and whether this product's
launch pattern (one microVM per run, short-lived) matches Firecracker's own
threat-model assumptions (its docs target long-running multi-tenant density,
e.g. Lambda).

### 4.2 Host-kernel exposure

Requires `/dev/kvm` access on the host — i.e., a Linux host with virtualization
extensions enabled and the KVM module loaded, and the process needs the
capability to open that device (jailer drops it to an unprivileged UID/GID after
setup but the initial setup needs it). This is a materially heavier host
precondition than `aa-isolation-native`'s Landlock+seccomp (needs only a
sufficiently new kernel, no special device access) or Sandlock. It is the same
class of precondition `aa-isolation-macos-vm` already has on macOS
(Virtualization.framework entitlement + codesigning, checked by
`MacosVmBackend::discover`, `aa-isolation-macos-vm/src/lib.rs:9-14`) — every
VM-based backend this product could have needs *some* privileged host capability
to set up, KVM is simply the Linux-specific instance of that same category.
**Unverified locally**: exact minimum privilege set the jailer needs versus what
a container-orchestrated or bare-metal deployment can grant without broader root.

### 4.3 Compatibility

A full Linux kernel in the guest means broad workload compatibility — the same
argument that makes `aa-isolation-macos-vm`'s guest Linux kernel workable for a
real toolchain (once AAASM-5849 baked one in). Firecracker's minimal device
model is the tradeoff: no GPU passthrough by default (no `vfio`/PCI passthrough
in the standard device model), limited emulated devices (virtio-net, virtio-block,
serial console, a handful of others — deliberately not a general-purpose VMM).
For a coding-agent workload (compilers, test runners, git, package managers,
network sessions — see ADR 0035's own "performance and compatibility constraint"
section, `adr/0035-....md:452-459`) this is likely acceptable; it is not
acceptable for any workload class that needs a GPU or unusual host devices.
**Unverified locally**: whether any current or planned `aa-devtool-*` adapter
needs anything Firecracker's device model cannot provide.

### 4.4 Startup cost

Firecracker's headline is ~125ms boot to init. That number, as commonly cited, is
measured against a minimal guest with essentially nothing in it — the same shape
as `aa-isolation-macos-vm`'s own measured ~300ms full round trip against a
*similarly minimal* guest (§3 above), before AAASM-5849's toolchain was added.
**The comparable, load-bearing number for this product is not either boot figure
— it is boot-plus-toolchain-ready for a guest that can actually run
`git`/`python3`/a real build.** Neither number is measured here; both are
plausible in the same rough range (hundreds of milliseconds), and the real
determinant will be image size and any lazy-loading strategy for guest
filesystem content, not the choice of VMM. This is exactly the kind of number
AAASM-6169's own acceptance criteria flags as needing "cold/restore
representative measurements... if hardware is available" — none is available
here, so this is stated as an open measurement, not a number.

### 4.5 Steady-state overhead

Each microVM needs its own guest kernel's resident memory plus whatever the
guest workload uses — Firecracker's docs cite a guest overhead on the order of a
few MiB for the VMM process itself, but the guest's own kernel and any resident
toolchain state add up per concurrent run. For N concurrent agent runs, memory
multiplies by N guest instances — the same shape `aa-isolation-macos-vm` already
has, per §3's finding that each launch boots its own independent guest with no
shared-image mechanism across concurrent runs. **Unverified locally**: actual
per-microVM steady-state RSS with a real toolchain guest under this product's
launch pattern.

### 4.6 Filesystem semantics

Firecracker exposes guest storage as virtio-block devices backed by host files
(typically raw disk images, or an overlay of a read-only base plus a writable
delta). This is the concrete mechanism behind its snapshot/restore feature
(§4.10) and is a genuinely different shape from `aa-isolation-macos-vm`'s
virtiofs-based shared-directory approach (`aa-isolation-macos-vm/src/paths.rs:5,35,87,108`
— a host directory is *shared into* the guest via virtiofs, not copied into a
block device). virtio-block-plus-snapshot is closer to what AAASM-6162 is
actually asking for ("Linux overlayfs / filesystem snapshot ... VM/container
disk-layer/snapshot mechanisms where appropriate") than virtiofs sharing is —
a virtio-block snapshot is a real, hypervisor-level copy-on-write disk image,
whereas virtiofs sharing has no transaction boundary at all (the shared
directory is just... shared, live, in both directions). This is the one area
where a Firecracker-style backend would be architecturally novel for this
product rather than "the same shape with a different VMM."

### 4.7 Network integration

Firecracker exposes virtio-net to the guest, backed by a host TAP device the
VMM's own network setup (or the jailer's netns) configures. AAASM-6163's
policy-governed egress broker would have to mediate at the **host** side of
that TAP device (or via a netns the microVM's TAP lives in) rather than inside
the guest — structurally the same integration point `aa-proxy`'s MitM approach
already assumes for the macOS VM backend's guest traffic (transport mediation
sits outside the confined process tree, ADR 0035 §5's rule applied to network
rather than filesystem). No new broker architecture is implied; Firecracker
would be one more attachment point for the same broker, not a reason to change
its design. **Unverified locally**: whether Firecracker's TAP-based networking
composes cleanly with `aa-proxy`'s existing MitM CA-trust model without a
per-guest cert-install step analogous to what the macOS backend's guest image
build already has to solve.

### 4.8 Child-process behavior inside the guest

Identical in kind to `aa-isolation-macos-vm`'s situation: process creation
inside the guest is invisible to the host supervisor except through whatever
the guest-side agent (this product's own `guest-init`/launch protocol,
`aa-isolation-vm-proto`) reports back. Firecracker itself has no opinion on
guest process supervision — that remains this product's own responsibility,
exactly as it is today for the VM guest. Nothing about Firecracker changes the
`aa-isolation-vm-proto` design; a Firecracker backend would reuse or fork that
same guest-side protocol rather than needing a new one.

### 4.9 Resource controls

The jailer applies cgroups to the Firecracker VMM process on the host side (CPU,
memory, and — depending on cgroup version — I/O ceilings), which is a real,
enforced-by-the-kernel resource ceiling on the *host* process representing the
microVM. This is more than `aa-isolation-macos-vm` currently has: §3 confirms
no host-side resource-ceiling enforcement is recorded for that backend today
(VM memory size is configured, but nothing enforces the *host process's*
ceiling the way a jailer cgroup would). If a Linux Firecracker backend shipped,
jailer cgroups would be a genuine, measurable resource-ceiling capability entry
(`CapabilityDomain` resource-ceiling domain) that the existing three backends
answer less completely.

### 4.10 Transaction support (assessed concretely, per the ticket's ask)

This is Firecracker's most distinctive capability and the one this spike was
specifically asked to weigh against AAASM-6162.

**What Firecracker's snapshot/restore actually does**: it serializes the full
guest state (vCPU registers, device state, guest memory) to disk, and can
restore a new microVM from that serialized state plus its backing memory file,
resuming execution from the exact point of the snapshot. Guest disk state is
whatever the virtio-block backing file held at snapshot time.

**Does this give AAASM-6162 something to build on?** Partially, and with an
important mismatch:

- Firecracker's snapshot/restore captures **the whole VM** (memory + device
  state + disk), which is a much heavier and coarser unit than AAASM-6162's
  stated need: a **filesystem-only** transaction boundary with
  commit/discard/diff semantics, ideally cheap enough to wrap a single agent
  action or a short run. A full-VM snapshot restore is closer to "resume this
  exact paused microVM later" (warm-pool reuse, which AAASM-6167/6169 both
  mention) than to "let this run write into an isolated layer, then either
  apply just the file diff or throw the whole layer away." The two are
  related but not the same primitive — AAASM-6162 explicitly needs a
  *change-set*/diff view of what happened, and a full-VM snapshot does not
  natively produce one; it produces "a paused VM you could restore," and
  anyone wanting a diff would still have to compute it by comparing the
  virtio-block backing file's before/after state (e.g. via overlay/qcow2-style
  backing-file semantics), not something Firecracker computes for you.
- The **virtio-block backing-file layer itself** (host files backing guest
  disks, potentially as a copy-on-write overlay over a shared read-only base)
  is the piece that maps cleanly onto AAASM-6162's "isolated copy-on-write
  layer" language — this is a real, usable COW mechanism, independent of
  whether the *VM-level* snapshot/restore feature is used at all. A Firecracker
  backend could offer this filesystem-layer COW as its transaction mechanism
  without necessarily using VM-level snapshot/restore for it.
- **State-hygiene risk, matching the ticket's stated security concern
  verbatim**: a restored/reused snapshot carries whatever the guest held at
  snapshot time — network connections, in-memory secrets, leases, previous
  run's writable state. Firecracker gives no built-in "clean the guest's
  residual state" primitive; it gives the opposite (perfect state fidelity),
  which is exactly the property that makes reuse dangerous without explicit
  hygiene work.

| Threat (this ticket's Security section, verbatim) | What Firecracker gives by default | What this product would have to build |
|---|---|---|
| Stale secrets/credentials cloned into a new tenant/run | Nothing — snapshot restore preserves guest memory exactly, including anything resident there | Explicit credential re-injection/rotation on every restore, same category as AAASM-5709's ambient-credential scoping work for process backends |
| Stale identity/session state cloned forward | Nothing — guest-side process/session state is part of the serialized memory | A guest-side reset hook invoked post-restore, before the confined workload runs, to clear identity bindings |
| Stale network state (open connections, ARP/DNS cache) cloned forward | Nothing — virtio-net device state is part of the snapshot | Re-initialize networking post-restore (new TAP attach, flush guest network stack) before re-enabling egress |
| Previous run's writable filesystem data leaking into a new run | Depends on backing-file design — a shared writable delta reused across restores leaks by construction; a fresh COW layer per restore does not | A **per-run** COW overlay atop a shared read-only base image, discarded (not reused) between tenants — this is a design choice this product owns, not something Firecracker enforces |
| Warm-pool re-key/re-bind (this ticket's explicit ask) | Nothing — Firecracker has no concept of "pool membership" or re-keying | A product-owned pool manager that snapshots only a known-clean guest state, and re-keys/re-binds identity+credentials+network on every checkout from the pool, never trusting the snapshot's own memory contents for identity |

**Concrete verdict on transaction support**: usable as a building block for the
filesystem-layer half of AAASM-6162 (virtio-block COW), **not** usable as a
turnkey implementation of AAASM-6162's commit/discard/diff contract, and
actively risky for AAASM-6167's warm-pool interest without the new,
product-specific re-key/reset work tabled above, none of which exists in this
codebase today for any backend.

### 4.11 Broker integration

Covered under §4.7 (network) for the egress broker specifically. No additional
integration point beyond what §4.7 already states — `aa-proxy` and the future
AAASM-6163 broker operate at the host/netns boundary regardless of which VMM is
underneath, per ADR 0035 §5's supervisor-stays-outside-the-boundary rule
applied uniformly across backends.

### 4.12 Attestation/evidence ability

Firecracker itself provides no attestation primitive beyond what the host KVM
setup could theoretically support (e.g., a TPM-backed measured boot of the host,
which is a host-platform concern, not something Firecracker adds). Any
`EnforcementEvidence` a Firecracker backend reports would follow the same
pattern the existing backends already use — the backend states what
`CapabilityDomain`s it enforces, observes, or cannot represent, mapped onto
ADR 0033 §6's terms — with **no new evidence primitive** available from
Firecracker itself that the existing backends lack. Per ADR 0035 §4's rule,
a Firecracker backend's *hardware-virtualization* boundary would likely
support a **Denied before execution** claim for filesystem/network/syscall
domains more completely than `aasm-native`'s Landlock+seccomp does today (a
full guest kernel confines everything, not just the specific syscalls/paths a
policy names) — but this is an architectural expectation, not a measured
result; the exact claim level requires the same measured-probe discipline
`MacosVmBackend::discover` and `aa-isolation-native`'s `capability::discover`
already hold themselves to (§3 above), which this spike did not perform.

### 4.13 Packaging/distribution — and the nesting question, made explicit

Firecracker requires a Linux kernel image and a root filesystem image **per
microVM class**, both of which this product would have to build, sign, version,
and patch — the same category of work AAASM-5849 already did once for the
macOS VM backend's guest image, and the same category of ongoing maintenance
implied there (guest toolchain drift, security patching of a second OS image
this product now owns). This is a real, recurring packaging burden, not a
one-time cost.

**The nesting point, stated explicitly because it changes the actual
comparison being made**: Firecracker is Linux + KVM only. It cannot run on
macOS at all. Whether it could run *inside* the existing `aa-isolation-macos-vm`
Linux guest depends on whether that guest can see a usable KVM device — and
this codebase does not configure or attempt that: nothing in
`aa-isolation-macos-vm` requests nested-virtualization CPU features or exposes
`/dev/kvm` to its guest (verified this pass — no "nested" reference in that
crate names anything but unrelated test/script nesting, §3). So **on this
codebase as it stands today, Firecracker is unreachable from the macOS-hosted
deployment**, full stop. Whether the underlying Apple Silicon platform could in
principle support nested virtualization for a future guest configuration is a
chip/OS-version question this spike did not measure and is not answered here —
the NO-GO below rests on what this product's code does today, not on an
unqualified platform-capability claim. This is a materially different
comparison than gVisor's (a userspace-kernel backend, which needs no KVM of
its own and so raises no nesting question at all — a question the parallel
AAASM-6168 spike addresses, out of scope here).

### 4.14 Licensing/supply-chain

Firecracker is Apache-2.0, AWS-maintained, and an active OSS project with
years of production use at AWS (Lambda, Fargate). This satisfies ADR 0035
decision 11's permissive-license preference cleanly — no worse a fit than
Sandlock's own licensing posture, and better than a copyleft alternative would
be. Supply-chain considerations: it is a single well-known upstream (fewer
transitive dependencies to track than a language-SDK-style dependency tree),
but shipping it means this product owns build/patch/signing of the kernel and
rootfs images it bundles (same burden category as any VM-based backend, see
§4.13), which is a supply-chain surface Sandlock/`aasm-native` do not have at
all (no guest OS image to maintain for either). **Unverified locally**: current
CVE history / patch cadence for Firecracker itself — worth a real check before
any ADR proposing to ship it, not performed in this desk-research pass.

### 4.15 Platform restrictions

Linux + KVM only, restated from §4.2/§4.13 for completeness against the
ticket's explicit ask: on the **current macOS-hosted deployment this product
ships**, this restriction makes Firecracker **inapplicable as this codebase is
built today** (§4.13) — there is no configuration of the current product that
reaches KVM from the host process or from the existing guest. On a
**hypothetical bare-metal or cloud Linux hosted-runtime deployment** (the kind
of deployment AAASM-6159's "Agent Execution Runtime 2.0" epic and AAASM-6163's
"hosted AASM workloads" language both gesture toward), the restriction is a
non-issue — that deployment target is Linux by construction, and KVM
availability there is a normal cloud/bare-metal precondition (already assumed
by e.g. any Kubernetes node offering `kata-containers` or similar). The two
contexts genuinely are different questions, which is why the verdict below is
split rather than singular.

### 4.16 Maintenance burden

Beyond the guest-image packaging burden (§4.13) and the supply-chain tracking
(§4.14), a Firecracker backend adds: a new `IsolationBackend` implementor to
keep in step with ADR 0035's negotiation contract (moderate — the trait is
already backend-neutral, per §2 above); a new guest-side integration surface
(likely reusing `aa-isolation-vm-proto` rather than inventing a new protocol,
per §4.8); new adversarial/conformance test coverage per ADR 0035's validation
requirements (`adr/0035-....md:813-824` — every backend needs conformance,
adversarial, compatibility and performance evidence, with negative controls);
and — if snapshot/restore is actually used per §4.10 — a wholly new state-
hygiene subsystem (re-key/reset on restore) that does not exist anywhere in
this codebase today for any backend. This is a materially larger maintenance
commitment than either of the two existing Linux backends (Sandlock,
`aasm-native`), comparable in kind to the macOS VM backend's own maintenance
history (AAASM-5849/5869/5870 are three real defects/gaps that backend
surfaced after shipping) but with a second OS image (kernel + rootfs) added on
top.

---

## 5. Conclusion — GO / CONDITIONAL GO / NO-GO, split by deployment context

**On the current macOS-hosted deployment: NO-GO.**
Firecracker requires Linux/KVM. This codebase's macOS VM backend does not
configure or expose nested virtualization to its guest (§4.13, verified by the
absence of any such configuration in `aa-isolation-macos-vm`), so there is no
path from the current shipping architecture to a running Firecracker instance.
This verdict rests on what the code does today, not on an unqualified claim
that the underlying hardware/OS could never support nesting — that broader
platform question was not measured here and is a separate investigation if it
ever becomes relevant. Nothing about this verdict is a comment on Firecracker's
quality; it is a comment on platform reachability from this codebase as it
stands.

**On a hypothetical bare-metal/cloud Linux hosted-runtime deployment:
CONDITIONAL GO.**
Conditions, in priority order:

1. **A real, product-specific need for VM-level or disk-layer snapshot/restore
   must exist first** — i.e., AAASM-6162 (transactional workspaces) or
   AAASM-6167 (warm pools) must actually decide they need it, rather than this
   spike creating demand for a feature in search of a requirement. §4.10 found
   Firecracker's snapshot/restore is a real but partial match for AAASM-6162's
   stated contract (full-VM granularity vs. a filesystem-diff need), so the
   fit should be re-checked against AAASM-6162's eventual concrete design, not
   assumed from this spike alone.
2. **Real KVM hardware measurement, not the public 125ms figure, before any
   startup-cost claim is made** — specifically cold-boot-to-toolchain-ready
   with a guest image carrying the same class of toolchain AAASM-5849 had to
   add to the macOS VM backend, and restore-from-snapshot latency for the
   same. Nothing in this spike measures either; both are stated as open
   questions per the ticket's own AC ("If hardware is available, cold/restore
   representative measurements are captured" — none was available here).
3. **An explicit state-hygiene design for any snapshot/warm-pool reuse**,
   covering exactly the five threats tabled in §4.10 (stale secrets, identity,
   network state, prior writable data, and pool re-key/re-bind) — this spike
   found no existing mechanism in this codebase that provides this for free,
   on any backend, VM-based or not.
4. **If a vertical slice is ever built, it must implement `IsolationBackend`
   using `ExecutionSpec`/`RuntimeRequirements` exactly as the existing three
   backends do** — no new capability vocabulary, no backend-named policy
   surface, per ADR 0035 decision 3. This spike's own survey (§2) confirms the
   trait needs no change to accept it.

**No hosted-production claim is made from this spike.** No PoC was built, no
hardware was available, and per the ticket's own AC this report explicitly
avoids fabricating hardware evidence from an unsupported (macOS) host. If a
follow-up ticket proceeds under the CONDITIONAL GO above, it should be scoped
as a real-hardware PoC ticket against the conditions listed, not as a
production backend delivery.

---

## 6. What this spike did not and could not assess

| Item | Why not assessed here | How to assess |
|---|---|---|
| Actual Firecracker boot/restore latency on real hardware | No Linux/KVM host in this session | Provision a bare-metal or nested-virtualization-enabled cloud Linux host with `/dev/kvm`; run Firecracker's own `getting-started` guide against a guest image built with this product's actual toolchain requirements |
| Jailer's real security effectiveness for this product's launch pattern | Requires adversarial testing against a running jailer, not documentation reading | Real-hardware adversarial suite, mirroring the pattern ADR 0035's validation requirements already mandate for every backend (`adr/0035-....md:813-824`) |
| Concurrent-microVM resource density at realistic fleet size | No infrastructure to run N concurrent microVMs | `wrk`-style N-instance harness once hardware exists, same shape as the AAASM-5269 spike's own "unmeasured, with a plan" table |
| Firecracker CVE/patch history and update cadence | Not performed in this desk-research pass | A dedicated supply-chain review before any ADR proposing to ship it |
| Whether AAASM-6162's eventual concrete transaction contract is actually satisfied by virtio-block COW | AAASM-6162 has no design yet — it is still To Do | Re-run this comparison once AAASM-6162 has a concrete contract |
| Whether the macOS host platform could in principle support nested virtualization for a future guest configuration | Chip/OS-version question, not a code question; not measured on this host in this pass | A dedicated platform capability check, separate from this codebase survey, only relevant if a specific future design proposes nesting |
