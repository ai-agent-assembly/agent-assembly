# AAASM-6170 — evaluating Apple Containerization as a macOS isolation substrate

Whether Apple's Containerization framework / `container` CLI (introduced at
WWDC 2025, GA alongside macOS Tahoe) is worth adopting as an additional, or
replacement, macOS execution-isolation backend for `aasm run`, next to the
custom Virtualization.framework (VZ) backend this repo already ships.

- **Ticket:** [AAASM-6170](https://lightning-dust-mite.atlassian.net/browse/AAASM-6170)
  (Task/Spike) · **Epic:** [AAASM-6159](https://lightning-dust-mite.atlassian.net/browse/AAASM-6159)
  "Agent Execution Runtime 2.0" · **Fix Version:** `agent-assembly v0.0.1-rc.8`
- **Compiled against** `remote/main` at `77cbbc8db`
- **Sibling artifacts:** the two other rc.8 substrate spikes running in
  parallel, [AAASM-6168](https://lightning-dust-mite.atlassian.net/browse/AAASM-6168)
  (gVisor) and [AAASM-6169](https://lightning-dust-mite.atlassian.net/browse/AAASM-6169)
  (Firecracker) — neither had a written report at the time this one was
  compiled, so no cross-spike template existed to match; the AAASM-6029 and
  AAASM-5534 verification-reports (see below) supplied the closest precedent
  for this repo's spike-report shape instead.
- **Read against:** [AAASM-5849](https://lightning-dust-mite.atlassian.net/browse/AAASM-5849)
  (guest toolchain), [AAASM-5869](https://lightning-dust-mite.atlassian.net/browse/AAASM-5869)
  (VM output forwarding), [AAASM-5870](https://lightning-dust-mite.atlassian.net/browse/AAASM-5870)
  (VZ concurrent-start fix), [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534)
  (host-wide mediation feasibility conclusions)

## Verdict

**CONDITIONAL GO — worth a real, hardware-verified proof-of-concept once the
macOS-version floor is confirmed acceptable to the product; do not replace,
weaken, or default away from the existing `aasm-macos-vm` backend.** This
matches the ticket's own acceptance criteria ("existing macOS backend remains
default unless a separate qualified migration decision is made") and this
Epic's explicit out-of-scope line ("making experimental gVisor/Firecracker/
Apple Containerization work the default before compatibility/security
evidence supports it").

The case for a PoC is real: Containerization's per-container VM model and OCI
compatibility would remove this repo's single largest self-inflicted gap
(AAASM-5849 — the guest has no general toolchain) at the framework level
instead of by hand-curating `GUEST_RESIDENT_PROGRAMS`, and it runs on the same
underlying Virtualization.framework this repo already trusts and is already
entitled for. The case against defaulting to it today is equally real: it
multiplies per-run VM overhead in a way this repo's own resource-ceiling work
(AAASM-6165) has not yet budgeted for, its sub-second-boot and per-container
isolation claims are Apple marketing claims this spike could not measure on
real hardware, and — the fact most likely to gate a PoC before it starts —
this repo has never documented a minimum macOS *version* for the VZ backend
(only an Apple Silicon *architecture* floor), so adopting a framework whose
own minimum OS requirement is unusually recent is a policy decision this
ticket does not have standing to make unilaterally. See
["Packaging/distribution"](#packaging-distribution-macos-version-floor) below
for exactly what is and is not documented today.

## What could and could not be verified in this pass

This spike was compiled by reading this repository's own shipped isolation
code and its existing, Done, real-hardware-qualified spike/verification
reports, plus this author's general knowledge of Apple's public
documentation and architecture for Virtualization.framework and
Containerization as of their public introduction. **No macOS host running
Containerization was available in this environment**, and no attempt was
made to install, boot, or benchmark `container`/`containerization` here.
Concretely, that means:

- Every claim about the *existing* `aasm-macos-vm` backend below (its
  boot-lock serialization, its lack of a network device, its fixed guest
  toolchain, its filesystem-only confinement, its lack of an Intel build) is
  read directly from this repository's own source and Done tickets — cited
  by file and line where practical — not recalled from memory.
- Every claim about Containerization's *sub-second boot*, *per-container VM*
  model, *OCI compatibility*, and *macOS-version floor* is this author's
  general knowledge of Apple's publicly announced architecture, **not**
  independently measured against a running installation. Where a specific
  number (boot time, memory overhead, exact OS build number) would matter to
  the verdict, it is marked **[vendor-claimed, unverified]** below rather than
  stated as fact. This spike's own accumulated project memory explicitly
  warns against exactly this failure mode for a sibling platform claim
  ("never claim Intel verification without an actual Intel Mac") — the same
  discipline applies here to every Containerization number this pass could
  not reproduce.
- No PoC code was written and no backend was wired in. This is a paper
  evaluation only, as the ticket's own "Prototype" section anticipates
  ("If viable, build the smallest backend/substrate adapter... " — this spike
  is the "if viable" gate, not the prototype itself).

## The existing backend, read from source (what this spike compares against)

`aa-isolation-macos-vm` (Epic AAASM-5811/5813/5837) implements the shared
`aa_isolation::IsolationBackend` trait — the same trait `aa-isolation-native`
(Linux Landlock+seccomp) and `aa-isolation-sandlock` implement — by
delegating confinement to `aa-isolation-native` running *inside* a
Virtualization.framework Linux guest, driven over a purpose-built
vsock/Unix-socket launch protocol (`aa-isolation-vm-proto`). The essential
architectural facts, all read directly from `aa-isolation-macos-vm/src/{lib,vmm,paths}.rs`
at `remote/main@77cbbc8db`:

- **One guest VM per prepared execution, not one shared long-lived guest.**
  `IsolationBackend::prepare` calls `vmm::boot`, which boots a fresh guest
  for every `PreparedExecution` and tears it down when the `Session` drops.
  There is no persistent, shared guest that launches route into — each
  `aasm run` gets its own ephemeral VM. This is closer to Containerization's
  per-container-VM model than the ticket's framing ("existing single-shared-
  VM-guest VZ backend architecture") suggests; the real architectural
  difference from Containerization is not shared-vs-per-run, it is
  **concurrency**, next.
- **Every boot on the host is serialized behind a single advisory file lock**
  (`vmm::BootLock`, AAASM-5870). Concurrent `VZVirtualMachine.start()` calls
  intermittently failed directory-sharing validation with `ENOENT` — root
  cause not fully characterized (closed-source framework internals), fixed
  by making no two boots ever race `start()` on this host. Practical
  consequence: two simultaneous `aasm run` invocations on the same host today
  queue behind each other for the duration of one full boot attempt, not
  because the architecture is single-guest, but because concurrent VZ boots
  were empirically unsafe. **This is the single most load-bearing fact for
  this spike's "does Containerization change the concurrency story"
  question** — see below.
- **Filesystem exposure is one virtiofs share of the launch's working
  directory, nothing else.** `paths::to_guest_path` refuses any host path
  that is neither under that share nor one of five fixed
  `GUEST_RESIDENT_PROGRAMS` (`aa-isolation-launch`, `busybox`, `git`,
  `python3`, `/bin/sh` — AAASM-5849). This is a deliberate security property
  (AAASM-5811 AC2: host secrets outside the project directory must be
  verifiably absent from the guest), not an oversight.
- **No network device is configured for the guest at all.** `vmm.rs`'s
  helper invocation never passes a `--network`-equivalent flag, and
  AAASM-5534's re-baseline states this explicitly: *"the macOS guest has no
  network device at all and sends `syscall_filter: None` on every launch"*
  (`verification-reports/AAASM-5534-host-wide-mediation-rebaseline.md:287-288`).
  Any network mediation this product does on macOS happens at the host
  process/proxy layer (`aa-proxy`), entirely outside this guest boundary.
- **Boot cost, as measured on the one host this Epic has qualified against:**
  `tests/real_hardware.rs`'s full round trip (boot, connect, launch, exit,
  teardown) measures at **~0.3s**, per `aa-isolation-macos-vm/src/lib.rs`'s
  own module docs. This is a real, cited, single-host measurement — not
  vendor marketing — and it is already in the same sub-second range Apple
  claims for Containerization's own per-container boot. Any startup-cost
  comparison below has to be read against this number, not against a naive
  assumption that the existing backend boots slowly.
- **Apple Silicon only; no Intel build exists.** Documented in
  `docs/src/quick-start/requirements.md:97` and
  `docs/src/security/execution-isolation.md:201,295` — "guest kernel/helper
  are arm64-only". **No macOS *version* floor is documented anywhere in this
  repository for this backend** — see
  ["Packaging/distribution"](#packaging-distribution-macos-version-floor).
- **Evidence tier is capped at `Configured`/`Installed`, never
  `Enforced`/`Measured`** — the guest kernel denies to the confined process,
  not to the host supervisor, so this backend (like `aa-isolation-native` on
  Linux) has no per-decision evidence channel (AAASM-6029's own spike
  conclusion, which this report does not re-litigate).

## Evaluation, dimension by dimension

### Threat boundary

Apple's Containerization model gives **each container its own lightweight
Linux VM**, individually boundaried by Virtualization.framework, with no
shared kernel between containers on the same host. Compared against what is
actually shipped here — one fresh VZ guest per `aasm run` invocation, torn
down on session drop — the *per-run* isolation boundary is not meaningfully
different in shape: both put a full Linux kernel between the confined
process and the host, both use VZ as the hypervisor, and neither shares a
guest kernel across concurrent unrelated workloads (Containerization by
design, this backend because nothing currently makes it share one). The
material difference is **process density inside one run**: this repo's guest
runs one confined process (plus its process tree) per boot, matching
`aasm run`'s one-invocation-one-launch model; Containerization's `container`
CLI is built around one VM per OCI *container*, which matters more once a
run needs several cooperating containers (a case `aasm run` does not
currently have — see ["Network integration"](#network-integration)).
**Not independently verified**: this repo could not confirm from documentation
alone whether Containerization's per-container VMs share a kernel *image* on
disk (COW) while remaining separately booted, or whether each is a fully
independent measured/attested boot — that distinction affects supply-chain
and attestation claims and would need real inspection.

### Host-kernel exposure

**Same trust model, same underlying primitive.** Containerization is built
directly on top of Virtualization.framework — the same framework class this
repo's own `MacosVmBackend` already drives via the Swift helper in
`aa-isolation-macos-vm-poc`. Adopting Containerization does not change what
mediates the host kernel boundary (the XNU hypervisor framework, Apple's own
trusted computing base) — it changes what *drives* that framework (Apple's
managed daemon/CLI versus this repo's own ~500-line Swift helper plus launch
protocol). This is a genuinely neutral-to-positive point for Containerization
on pure host-kernel exposure: it removes this repo's custom helper binary
(and its `com.apple.security.virtualization` entitlement surface,
AAASM-5840) from the trusted path, at the cost of trusting Apple's own
container daemon binary instead. Neither is verified against the other's
actual attack surface in this pass.

### Compatibility

**This is Containerization's strongest, least speculative advantage.** OCI
image compatibility would let `aasm run` consume standard container images
directly, which structurally *dissolves* AAASM-5849's finding rather than
working around it — the current backend's answer to "the guest has no
python/node/git" is a hand-picked five-binary allowlist
(`GUEST_RESIDENT_PROGRAMS`) that AAASM-5849 itself flagged as a real gap ("a
usable dev toolchain is plausibly hundreds of MB to multiple GB" if baked in,
or a security-widening host-filesystem share if not). An OCI-image-based
guest would let an operator pick an image with the toolchain a given
`aa-devtool-*` adapter actually needs, without this repo maintaining a guest
rootfs build script (`scripts/build-guest-rootfs.sh`) by hand. This is the
one dimension where this spike recommends taking Apple's public claim at
close to face value, because it follows from Containerization's documented
architecture (an OCI-compatible image puller and per-container filesystem)
rather than from a performance number that needs a stopwatch to confirm.

### Startup cost

**[Partially vendor-claimed, partially measured against this repo's own
number.]** Apple's public claim is sub-second boot per container. This
repo's *own, real-hardware-measured* number for the existing backend's full
boot-connect-launch-exit-teardown round trip is **~0.3s** on the one host
this Epic qualified against (`aa-isolation-macos-vm/src/lib.rs` module docs).
These are not directly comparable measurements — different hosts, different
guest images, different definitions of "boot" — but they are close enough in
order of magnitude that startup cost is **not** a strong differentiator
either way without a same-host, same-workload comparison. **Not verified**:
whether Containerization's claimed number includes OCI image resolution/pull
time (which the existing backend has no equivalent of, since its rootfs is a
pre-built local artifact) or only measures a warm-cached boot.

### Steady-state overhead

**This is where the two architectures genuinely diverge, and it is directly
relevant to AAASM-6165's resource-ceiling work.** The existing backend's
resource story is "one guest, sized for one confined process, alive for the
duration of one `aasm run`" — AAASM-6165's own ticket already names the
mechanism to budget: *"host VM vCPU/RAM ceilings plus in-guest limits on
macOS VM"*, a single ceiling per run. Containerization's per-container-VM
model means an agent workflow that wants several cooperating processes
(e.g., a database plus an app server plus the agent itself) multiplies that
cost by container count — N separate Linux kernels, N separate VM memory
floors, instead of N processes inside one guest's process tree. For AASM's
actual current usage shape — one `aasm run` launching one confined program
(plus its child processes, all inside one guest) — this multiplication does
not apply; it would only bite if AASM itself starts modeling a governed
agent workflow as multiple OCI containers rather than one guest with an
allowed process tree, which is not this repo's current design. **Flag for
AAASM-6165**: if a future design does move toward multi-container agent
workflows, the resource-ceiling schema needs a per-container multiplier this
spike did not see anticipated anywhere in that ticket's text.

### Filesystem semantics

Containerization provides per-container filesystem via its own layered/OCI
image model (each container gets its own writable layer over shared,
content-addressed image layers) — a materially different shape from this
backend's current single virtiofs share of the host working directory. This
is directly relevant to **AAASM-6162** (transactional COW workspaces):
Containerization's per-container filesystem layer is architecturally closer
to what AAASM-6162 wants (an isolated, discardable writable layer with a
measurable diff against a base) than the current backend's virtiofs share,
which has no COW semantics of its own — any transactional behavior on top of
`aasm-macos-vm` today would have to be built in the shared host directory
(e.g., via a Git worktree or overlay on the host side), not inside the VM
boundary. **Not verified**: whether Containerization's per-container layer
is host-visible/inspectable in a way AASM's evidence pipeline could read a
diff from without shelling into the container, or whether that would require
a new evidence-collection mechanism of its own.

### Network integration

The existing backend, as established above, gives the guest **no network
device at all** — network mediation for macOS happens entirely outside this
boundary, at the `aa-proxy` host process layer. Containerization, by
contrast, is built around per-container networking (each container gets its
own network namespace/interface, with Apple's `container` CLI managing
per-container IP assignment for inter-container and container-to-host
traffic) — a capability this repo's current guest has zero equivalent of.
Adopting Containerization would not, by itself, improve or worsen the
`NetworkEgress` gap AAASM-5534 already recorded (`aasm-native` reports it
`Unsupported`, and the macOS guest currently sidesteps it by having no guest
network stack to mediate) — it would just relocate where a *future*
guest-side network boundary could be built, from "does not exist" to "exists
but is not yet policy-driven." No egress broker attaches to it today either
way.

### Child-process behavior

Both models confine a process tree inside a guest kernel — Landlock/seccomp
via `aa-isolation-native` running inside the guest, applied to whatever
process tree the launched program spawns, matches `DescendantCoverage::ProcessTree`
the same way it does for the native Linux backends. Containerization's own
child-process story (a container's PID namespace, its own init) is
structurally similar at the confinement level; the practical difference is
that `aa-isolation-macos-vm`'s launch protocol (`aa-isolation-vm-proto`) is a
purpose-built, minimal wire protocol this repo controls end-to-end, while a
Containerization-based backend would need to translate AASM's `ExecutionSpec`
into whatever process-launch surface `container run`/the Containerization
Swift API actually exposes — unverified in this pass how granular that
surface is (e.g., whether stdio capture is as directly available as the
existing `Message::LaunchOutcome` wire message this repo already built for
AAASM-5869).

### Resource controls

Containerization has its own per-container CPU/memory allocation (part of
its container-spec model, analogous to Docker's `--cpus`/`--memory`).
Whether this exposes a Rust-callable API fine-grained enough to feed
AAASM-6165's planned `ResourceSpec/ResourceCapability` abstraction is
**unverified** — this spike could not inspect the actual Containerization
Swift package API surface without a working installation. The existing
backend's own resource story is likewise not yet built (AAASM-6165 is a
`To Do` sibling Story under the same Epic, not Done), so this is a wash: both
paths currently require AAASM-6165's work to land before either backend can
make a resource-ceiling claim.

### Transaction support

No transaction/COW workspace exists in either the current backend or a
hypothetical Containerization-backed one today — AAASM-6162 is `To Do`.
Containerization's per-container filesystem layer (noted under "Filesystem
semantics" above) is the more natural substrate to build AAASM-6162's
commit/discard semantics against than the current flat virtiofs share, if
this repo ever adopts it, but that is a design opportunity, not a shipped
capability either framework currently gives AASM for free.

### Broker integration

Neither this repo's credential broker work (`aa-isolation/src/ambient.rs`
`EnvironmentPlanner`, per AAASM-5534's own re-baseline) nor its egress broker
concept currently reaches inside the macOS guest boundary at all — credential
handling for the existing backend is bounded by what environment variables
`MacosVmBackend::set_child_environment` places on the `LaunchRequest`, with
no in-guest credential-token exchange. A Containerization-based backend would
face the identical integration question: a broker would need to inject
credentials at container-launch time (analogous to the existing
`child_environment` mechanism) since there is no existing hook inside either
framework for a live broker round-trip *during* guest execution. Adopting
Containerization does not, by itself, solve or worsen this — it is an
AASM-side integration this repo has not built against either substrate.

### Attestation/evidence ability

The existing backend's evidence ceiling is `Configured`/`Installed` only —
AAASM-6029's own spike already established that neither this backend nor any
other shipped one can produce a per-decision `Enforced`/`Measured` record,
because guest-kernel denials never reach the host supervisor. Nothing in
Containerization's public architecture changes that structural fact: a
denial from Landlock/seccomp *inside* a Containerization-managed guest is
just as invisible to the host as it is inside this repo's own guest, unless
AASM builds its own in-guest evidence-reporting agent for either substrate —
a cost identical on both sides. Containerization's own image provenance
(OCI manifest digests, potentially signed images) is a genuinely new
evidence *surface* this backend does not have today (there is no "which
image did this guest boot" claim to make when the rootfs is a locally-built
gitignored artifact) — this is a real, if narrow, attestation advantage
Containerization would add, not one that closes the existing per-decision
gap.

### Packaging/distribution (macOS version floor)

**This is the fact most likely to gate or block a real PoC, and it needed
the most care to state honestly.** Apple's Containerization framework
[vendor-claimed, unverified in this pass against a running installation]
requires a materially newer macOS baseline than this product has ever needed
for anything else it ships — publicly documented as targeting the macOS
Tahoe (26) generation at general availability. This repository's *own*
documentation was searched exhaustively for a macOS version floor to compare
against, and **none exists**:

- `docs/src/quick-start/requirements.md:97` and
  `docs/src/security/execution-isolation.md:201,295` document an **Apple
  Silicon architecture** requirement for `aasm-macos-vm` — never a macOS
  *version* number.
- The only macOS version number found anywhere in this repository's docs is
  `docs/src/devtools/managed-device-measurement.md:80` ("macOS 13 or newer"),
  which is scoped to an unrelated feature (`/Library/Application Support`
  managed-device refusal behavior for the Claude Code devtool integration),
  not to execution isolation or to a product-wide minimum-OS policy.
- No `README.md`, `CONTRIBUTING.md`, or `docs/src/compatibility.md` statement
  of a general minimum supported macOS version was found.

**Consequence**: there is no existing floor for this ticket to check
Containerization's requirement against, which means the honest AC-mapped
answer to "check whether that's compatible with this repo's documented
minimum-macOS support policy" is: **no such policy is documented, so
compatibility cannot be confirmed — it can only be flagged as an open
product decision.** If Containerization's actual floor is as recent as
publicly reported, adopting it as anything more than an opt-in experimental
backend would, for the first time, force this product to pick and document
a minimum macOS version — a decision with product-wide packaging
consequences (every current user on an older-but-still-Apple-Silicon macOS
release would lose eligibility for this backend specifically, while
remaining eligible for the existing `aasm-macos-vm` backend, which has no
such floor). This must be resolved as an explicit product decision before
any PoC, not discovered by a user's `container` invocation failing at
runtime.

### Licensing/supply-chain

Containerization is Apple's own framework — Apple has open-sourced parts of
it (the `container` CLI and supporting Swift packages have been published
under an open license), but the underlying Virtualization.framework and the
`container` runtime's integration with it remain Apple-controlled,
closed-source system frameworks, not an independently auditable, portable
mechanism in the way gVisor or Firecracker are (both fully open-source
sandboxes this repo's sibling spikes, AAASM-6168/6169, are separately
evaluating). This is a real, structural constraint on inspectability and
portability: this repo cannot patch, audit, or reason about
Virtualization.framework's internal behavior any more than it already
cannot for the existing `aasm-macos-vm` backend — Containerization does not
make this worse, since both sit on the same Apple-owned hypervisor
framework, but it also does not make it better. Where Containerization does
add a *new* supply-chain surface is the `container` CLI/daemon binary and
its OCI image-pull pipeline, both external to this repo and both a new
maintenance/pinning dependency the current backend does not have (the
current backend's only external binary dependency is this repo's own
hand-built Swift helper).

### Platform restrictions

**[Vendor-claimed, unverified — treat with the same caution this repo's own
project memory already insists on for Intel claims.]** Containerization,
like Virtualization.framework generally for Linux-guest boot, is publicly
documented as Apple Silicon only; no Intel Mac support is claimed by Apple
for it. This spike did not have Apple Silicon *or* Intel hardware with a
qualifying macOS version and Containerization installed, so this claim is
carried forward from Apple's public documentation, not independently
confirmed. Consistent with this repository's own standing rule for the
existing backend (documented, hardware-verified: "macOS (Intel) ❌ Not
supported"), any product statement about Containerization's Intel support
must likewise be stated as **unverified/vendor-claimed**, never asserted as
measured fact, until real Intel hardware (which would not run
Containerization at all per Apple's own claim) or real Apple Silicon
hardware with Containerization installed is used to check it directly.

### Maintenance burden

The existing backend's foundation, Virtualization.framework, is a mature,
multi-year-stable Apple API (introduced 2019, extended steadily since) that
this repo already depends on directly and has already qualified on real
hardware three times over (AAASM-5811/5837/5870). Containerization is a
framework Apple introduced in 2025 — it has no comparable track record, and
Apple has historically iterated aggressively on newer frameworks in their
first several OS cycles (entitlement requirements, API surface, and CLI
behavior are all plausible targets for near-term change). Depending on it
trades a dependency this repo already understands and has stabilized
against for one Apple could still meaningfully reshape before this repo's
next few release cycles complete. This is a genuine argument for keeping
Containerization experimental/opt-in far longer than the existing backend
was, independent of any security or compatibility finding above.

## Mapping against AAASM-6170's own acceptance criteria

| AC | Status this spike delivers |
|---|---|
| Current custom VZ vs. Apple Containerization comparison is evidence-backed | Delivered above, dimension by dimension — cited to this repo's own source/tickets where the claim is about the existing backend, explicitly flagged vendor-claimed/unverified where it is about Containerization |
| Platform/version/architecture limitations are explicit | Delivered — see ["Packaging/distribution"](#packaging-distribution-macos-version-floor) and ["Platform restrictions"](#platform-restrictions); the macOS-version-floor gap is the headline finding |
| Existing AASM security properties are mapped property-by-property, not assumed equivalent | Delivered per-dimension above; no property is asserted equivalent without a stated basis, and several (attestation, network, evidence) are explicitly *not* improved by Containerization alone |
| If viable, minimal experimental vertical slice runs existing boundary tests on real compatible hardware | **Not attempted this pass** — no qualifying hardware/OS/framework installation was available; this is the PoC this spike recommends as a *follow-up*, not something this spike itself could execute |
| Startup/concurrency/compatibility measurements are recorded | Startup: partially (this repo's own ~0.3s number is real; Containerization's sub-second claim is not independently measured). Concurrency: not measured for Containerization; this repo's own AAASM-5870 serialization constraint is recorded. Compatibility: OCI compatibility is architectural, not benchmarked |
| Go / Conditional Go / No-Go decision exists | **Conditional Go** — see [Verdict](#verdict) |
| Existing macOS backend remains default unless a separate qualified migration decision is made | This spike does not change any default and recommends none change as a result of it |

## What a real PoC should measure, if pursued

Not built here — recorded so the follow-up ticket does not have to
re-derive it:

1. Actual macOS version floor Containerization enforces at runtime, on real
   hardware, checked against whatever minimum-macOS policy the product team
   sets in response to this spike's finding that none currently exists.
2. Real boot-time and steady-state memory measurement for a single
   Containerization-backed launch, same host class this Epic already
   qualified the existing backend on, for a true apples-to-apples number
   against the existing ~0.3s figure.
3. Whether concurrent Containerization container starts hit any analogue of
   AAASM-5870's `VZVirtualMachine.start()` race, or whether Apple's own
   daemon already serializes/queues internally — this determines whether a
   Containerization backend would need its own `BootLock`-equivalent.
4. Whether the Containerization Swift API exposes stdout/stderr capture at
   least as directly as the wire protocol AAASM-5869 already built, so a
   backend adapter would not regress operator-visible output.
5. Whether an OCI image's filesystem layer is host-inspectable enough to
   produce an `EvidenceRecord` without a new in-guest agent — relevant to
   both attestation and AAASM-6162's transactional workspace design.

## Scope fences

This spike does not:

- Modify any Rust source, add a backend, or change any default backend
  selection.
- Claim Containerization is faster, safer, or more compatible than the
  existing backend in any dimension this spike could not independently
  verify — every such claim above is explicitly marked vendor-claimed.
- Resolve the macOS-version-floor product decision — that is named as an
  open question for the product team, not answered here.
- Duplicate AAASM-5534's host-wide mediation conclusions, AAASM-6029's
  per-decision evidence conclusion, AAASM-5869's output-forwarding fix, or
  AAASM-5870's concurrent-boot fix — each is cited, not re-derived.
