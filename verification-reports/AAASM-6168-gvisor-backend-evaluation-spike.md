# AAASM-6168 — gVisor/runsc as an `IsolationBackend` candidate

Whether gVisor/runsc is worth building as a new backend under the existing
`aa-isolation::IsolationBackend` contract, for coding-agent workloads that need
more POSIX compatibility than the WASM/WASI tool sandbox
([AAASM-1965](https://lightning-dust-mite.atlassian.net/browse/AAASM-1965))
and stronger host-kernel mediation than the native Landlock/seccomp backend.

- **Ticket:** [AAASM-6168](https://lightning-dust-mite.atlassian.net/browse/AAASM-6168)
  (Spike) · **Epic:** [AAASM-6159](https://lightning-dust-mite.atlassian.net/browse/AAASM-6159)
  — Agent Execution Runtime 2.0 · **Goal:** CBLPCRLM-37 · **Target:**
  `agent-assembly v0.0.1-rc.8`
- **Consumed by:** [AAASM-6167](https://lightning-dust-mite.atlassian.net/browse/AAASM-6167)
  (evidence-aware runtime classes / property-based backend selection) — this
  document exists to give that planner a truthful property bundle for gVisor,
  not to wire it in.
- **Compiled against** `remote/main` at `77cbbc8db`
- **Method precedent reused:** [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534)'s
  re-baseline and the [AAASM-6029 per-decision evidence
  spike](AAASM-6029-per-decision-prevention-evidence-spike.md) — same discipline
  (ground every AASM-side claim in a file read at a pinned SHA, mark every
  gVisor-side claim as documentation-derived or unmeasured, do not blur
  `requested`/`selected`/`available`/`enforced`/`measured`/`degraded`/
  `unsupported`/`unmeasured`). This document does not re-derive 5534's
  platform-feasibility conclusions; it answers a narrower, backend-specific
  question 5534 explicitly left to a follow-up spike.

## Verdict at a glance

**CONDITIONAL GO** — worth a scoped follow-up prototype ticket under
`aa-isolation`, gated on the measurements this document could not make without
a Linux host. Not a GO, because nothing below is measured against a real
coding-agent workload; not a NO-GO, because ADR 0035 already names gVisor as
exactly this kind of candidate and nothing found here contradicts that. See
[Conclusion](#conclusion--go--conditional-go--no-go) for the full call.

## Scope and what this document is not

Per the ticket's own "Out of scope" list and this pass's explicit
instructions:

- This is a **documentation-only** evaluation. No Rust source, `Cargo.toml`,
  or CI configuration is touched by this ticket.
- **This does not build the ticket's requested vertical slice.** AAASM-6168's
  acceptance criteria ask for a real `ExecutionSpec`/planner-driven prototype
  with measured compatibility, measured overhead, and a negative control. None
  of that is done here — this pass produces the architecture/compatibility
  matrix and threat-boundary analysis those criteria also require, and
  explicitly defers the measurement-dependent criteria to a follow-up. That
  gap is named, not hidden, in [Method and limits](#method-and-limits) and
  restated in the [Conclusion](#conclusion--go--conditional-go--no-go).
- **No default-selection change occurs.** Nothing here alters
  `aa-isolation`'s auto-selection behavior, and a PoC — if a follow-up ticket
  builds one — would not itself confer default eligibility. That decision
  belongs to AAASM-6167's property-based planner, once gVisor has a measured
  `BackendCapabilities` report to feed it.
- **This does not claim VM-equivalent isolation for gVisor.** gVisor is a
  userspace-kernel boundary sharing the host kernel underneath it, not a
  hardware-virtualized guest kernel. See
  [Threat boundary and host-kernel exposure](#threat-boundary-and-host-kernel-exposure).

## Method and limits

| Source | What it settles |
| --- | --- |
| `aa-isolation/src/backend.rs`, `capability.rs`, `evidence.rs` at `77cbbc8db` | The exact contract a gVisor backend would implement: `IsolationBackend`'s five-plus-two stages, `CapabilityReport`'s six independent axes, `EvidenceKind`'s five grades, `PlatformBoundary` (already names `UserspaceKernel` as a variant distinct from `SharedHostKernel`/`GuestKernel`) |
| `aa-core/src/attestation.rs` at `77cbbc8db` | `ClaimTerm`'s eleven-term vocabulary and `asserts_coverage`/`is_prevention` — used throughout to avoid claiming prevention where only observation would be honest |
| `docs/src/adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md` | The ratified architecture gVisor would join: it is named explicitly as a "userspace kernel" example (line 459), a licensing preference for Apache-2.0/MIT/BSD backends (line 445), and reconsideration trigger 3 ("gVisor/userspace-kernel or microVM execution becomes a default") |
| `aa-isolation-sandlock/src/lib.rs`, `backend.rs` | The existing precedent for driving a third-party isolation mechanism as an **external OCI-style executable over argv**, rather than linking it as a Rust crate — the integration shape a gVisor backend would most plausibly reuse |
| `aa-isolation-macos-vm/src/lib.rs` | The one existing backend whose `PlatformBoundary` is `GuestKernel` rather than `SharedHostKernel` — the closest in-tree comparison point for what a stronger-than-native boundary costs in evidence completeness (see [AAASM-6029 finding F2](AAASM-6029-per-decision-prevention-evidence-spike.md#f2---macosvmbackendevidence-returns-no-records-at-all): its `evidence()` still returns zero records) |
| `AAASM-6029-per-decision-prevention-evidence-spike.md` | That **no shipped backend today** produces per-decision (`EvidenceKind::Decision`) evidence, and that the `IsolationBackend` contract already has everywhere such evidence would need to be emitted — the baseline gVisor's attestation story is compared against |
| gVisor's own public architecture documentation (`gvisor.dev/docs/architecture_guide`), the 2018 USENIX gVisor paper, and general knowledge of `runsc`'s Sentry/Gofer design (training-data knowledge, not fetched live in this session) | Every claim in this document about gVisor's internals |

**Two honest limits, stated up front rather than discovered by a reader:**

1. **No Linux host, and no gVisor installation, was available in this
   session.** Every gVisor-side claim below is either (a) architectural, drawn
   from gVisor's own published design documentation and general knowledge of
   how `runsc` works, or (b) explicitly marked `unmeasured — needs a local
   benchmark`. Where a number appears (startup overhead, binary size), it is
   attributed as a **recalled, not independently re-verified** figure from
   gVisor's own public materials, and the document says so at each occurrence
   rather than presenting it as measured against this repository's workloads.
   No number in this document should be read as this repo's own benchmark
   result.
2. **The ticket's own acceptance criteria ask for measurement this pass
   cannot produce.** "Real representative workload compatibility is measured,
   not inferred" and "Performance/startup overhead is measured against an
   appropriate existing backend" are both criteria this document does not
   satisfy — it infers, from documentation, what those measurements would
   likely show, and says explicitly where inference stops being trustworthy
   enough to act on without a real run. That distinction is the entire point
   of the vocabulary in `aa-isolation/src/capability.rs`: an inferred
   `SupportLevel` is not the same fact as a measured one, and this document
   does not blur them.

## The candidate, in this codebase's terms

`aa-isolation` defines `IsolationBackend` as an object-safe trait with five
lifecycle stages (`capabilities` → `plan` → `prepare` → `spawn` → `evidence`,
plus `wait_for_exit`/`terminate` for supervision, `aa-isolation/src/backend.rs:277-381`).
A gVisor backend (call it `aa-isolation-gvisor`, following the
`aa-isolation-<mechanism>` naming already used by `aa-isolation-native` and
`aa-isolation-sandlock`) would implement that trait by driving `runsc` as an
external OCI-compatible container runtime — the same integration shape
`aa-isolation-sandlock` already uses to drive Sandlock as an external
executable over argv, not a linked Rust crate. This is a real, non-speculative
precedent already in the workspace, and it materially lowers the integration
risk relative to inventing a new process-control mechanism.

`BackendCapabilities::platform_boundary()` already has a variant for exactly
this backend's shape: `PlatformBoundary::UserspaceKernel`
(`aa-isolation/src/capability.rs:367-374`), distinct from
`SharedHostKernel` (native/Sandlock today) and `GuestKernel` (the macOS VM
backend). No new enum variant is needed to represent gVisor honestly in this
contract — that is itself evidence the ADR 0035 authors designed this
vocabulary with gVisor specifically in mind (ADR 0035 names it by name at
lines 436, 459, 546, 732, 836).

## Threat boundary and host-kernel exposure

**What gVisor actually intercepts.** `runsc`'s Sentry is a user-space kernel,
written in Go, that runs as an ordinary (unprivileged, from the host's point
of view) process alongside the sandboxed application. The application's
syscalls are redirected to the Sentry instead of reaching the host kernel
directly, using one of two platforms:

- **`ptrace` platform** — the Sentry attaches to the application via
  `ptrace(2)`, traps every syscall, and services it itself. Portable (works
  anywhere `ptrace` works, including inside containers and nested
  virtualization), but pays a context-switch cost per syscall.
- **`systrap`/KVM platforms** — newer, lower-overhead interception paths
  (`systrap` uses a seccomp-BPF trap plus a shared-memory stub rather than
  full ptrace tracing per syscall; the KVM platform runs the Sentry in a
  separate guest address space using hardware virtualization extensions
  purely to get faster context switches, not to add a second kernel).

In every mode, the *residual* host-kernel exposure is the syscall surface the
Sentry itself makes to service the application — implementing ~200 of Linux's
~350-plus syscalls in Go, rather than the application's full native syscall
surface reaching the real kernel. This is the architectural claim gVisor
makes for itself: a materially smaller trusted-kernel-code-path than a
directly-scheduled process, without the cost of a second kernel. It is *not*
the same guarantee as Firecracker/microVM-style hardware-enforced memory
isolation, and ADR 0035 (line 459) already states this distinction correctly:
*"a process sandbox shares more host-kernel attack surface than a userspace
kernel or VM"* — gVisor sits in the middle of that spectrum, not at either
end.

**What this means for `CapabilityReport`.** If measured (not assumed) to hold
on a real host, a gVisor backend's `Syscall` domain report would plausibly
claim `Mediation::Enforce`, `DecisionTiming::Pre`, `Synchrony::Sync` —
the shape `can_prevent()` requires — because every intercepted syscall is
resolved by the Sentry before any host-kernel effect occurs. That is a
stronger claim than either shipped Linux backend can make today for the
`Syscall` domain specifically: `aa-isolation-native`/`aa-isolation-sandlock`
rely on Landlock (filesystem-scoped, not general-syscall) and seccomp-BPF
(which can deny specific syscalls but does not re-implement general syscall
*semantics* the way a userspace kernel does). **This is an architectural
claim, not a measured one** — it depends on gVisor's actual `runsc` build
correctly closing every escape identified in its own CVE history (gVisor has
shipped several security advisories over its life for Sentry escapes;
general knowledge, not independently re-verified in this session), and on the
Gofer/network-stack processes carrying no separate exploitable surface. A
production claim would require the same kind of adversarial conformance work
[AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532)
already runs against the existing backends.

**Residual host-kernel exposure, concretely:** the syscalls the Sentry itself
issues to the real kernel (memory management, its own I/O to the Gofer, its
own scheduling), the Gofer process's own syscall surface (it does perform real
filesystem I/O on the host), and — in `hostinet` network mode specifically —
a deliberately widened surface, since `hostinet` hands network syscalls
through to the host stack for performance rather than routing them through
gVisor's own userspace `Netstack`. **A gVisor deployment that enables
`hostinet` for performance is trading away part of the network mediation
claim above.** This trade-off would need to be represented explicitly in
`CapabilityReport::with_support(SupportLevel::Partial { limitations })` for
the `NetworkEgress` domain, not silently assumed away.

## Compatibility

gVisor's stated goal is running **unmodified Linux ELF binaries** — a strict
superset of what the WASM/WASI backend (AAASM-1965) can execute (compiled
WASI modules only). Known-unsupported or partial areas, from gVisor's own
published compatibility documentation and general knowledge (unverified
against the current `runsc` release in this session — **flagged, not
measured**):

- Historically limited or absent support for certain newer syscalls (`io_uring`
  had long-standing gaps), specific `ioctl`s, and some `/proc`/`/sys` entries
  used by low-level tooling.
- `ptrace`-based debugging *of a process running inside gVisor* has
  historically been restricted, because the Sentry itself already occupies the
  tracer role the host would normally provide — relevant if a coding agent's
  workload includes a debugger or a tool that expects to `ptrace` its own
  children.
- Some `mmap`/`MAP_SHARED` file-backed semantics and advanced filesystem
  notification (`inotify`) had gaps in earlier releases; gVisor's changelog
  shows steady closure of these over time, which means **this list ages
  quickly and must be re-checked against the pinned release before any
  compatibility claim ships**, not treated as settled by this document.
- GPU/accelerator passthrough exists via an explicit opt-in integration
  (`nvidia-container-runtime`-style), not by default.

**Coding-agent relevance.** The workloads named in the ticket (Claude/Codex-
style agents that traverse repositories, invoke compilers, run `git`, install
packages) are POSIX-heavy but not exotic — they do not typically need
`io_uring`, raw `ptrace` of children, or GPU passthrough. The honest read is
that gVisor's *known* gaps are unlikely to be this workload's bottleneck; its
*unknown* gaps (whatever a real run surfaces) are exactly what AAASM-6168's
own acceptance criterion — "real representative workload compatibility is
measured, not inferred" — exists to find, and this document cannot substitute
for that run.

## Startup cost

**Unmeasured against this repo's workloads.** gVisor's own published
benchmarks (recalled from general knowledge of the project, not re-fetched or
re-verified this session) have historically reported container-start overhead
in the tens-of-milliseconds range above a native container start, and faster
cold-start than a full microVM boot (Firecracker's own published boot times
are commonly cited in the ~125ms range; gVisor's Sentry initialization is
typically faster since it is not booting a second kernel). Treat both figures
as **recalled from public material, not measured here** — the only trustworthy
next step is `hyperfine`-style repeated cold starts of `runsc run` against
`aa-isolation-native`'s process spawn on the same host, which this session
cannot perform.

## Steady-state overhead

**Unmeasured against this repo's workloads; architecturally predictable
direction.** Syscall-heavy, small-file-heavy workloads (exactly what a
coding agent traversing a repository and invoking a compiler does) are
gVisor's worst case, because every syscall pays a Sentry round-trip that a
native process does not. gVisor's own project material documents this as the
motivating case for its `directfs`/overlay optimizations (trusted host file
descriptors passed through for known-safe directories, bypassing the Gofer
round-trip for those paths) — but whether that optimization is compatible
with this codebase's filesystem-scope policy model (`aa-isolation`'s
per-path allow-list, ADR 0035's AAASM-5751 amendment) is itself an open
question a prototype would need to answer, not this document.

## Filesystem semantics

gVisor mediates filesystem access two ways:

1. **Gofer/9P (or gVisor's newer `lisafs` protocol)** — a separate host-side
   process performs real filesystem I/O on the Sentry's behalf and returns
   results over an RPC-like protocol. This is the default, fully-mediated
   path: every filesystem operation the sandboxed process makes is visible to
   and can be denied by the Gofer, which is a genuine `DecisionTiming::Pre`
   mediation point — but it has historically been the dominant source of
   gVisor's filesystem-latency overhead for metadata-heavy workloads
   (`stat`, small-file `open`/`close` loops — again, exactly what a compiler
   toolchain or `node_modules`-style dependency tree produces).
2. **`directfs`/overlay passthrough** — for directories the Sentry trusts,
   host file descriptors are handed through directly, trading some of the
   Gofer's mediation strength for performance. Any backend built on this
   would need to report that trade honestly per path, likely as
   `SupportLevel::Partial` on `FilesystemRead`/`FilesystemWrite` for the
   passthrough paths specifically, not as a blanket `Full`.

Neither path is measured here. The direction (Gofer path pays real latency
for exactly the filesystem-access pattern coding-agent workloads produce) is
architectural, not benchmarked.

## Network integration

gVisor ships its own userspace network stack, **Netstack** — TCP/IP
implemented in Go inside the Sentry, so outbound connections are mediated by
gVisor before any packet reaches a host socket. This is a genuinely different
and additional mediation point from this repo's existing network-egress
control (`aa-proxy`'s MitM sidecar), not a replacement for it: `aa-proxy`
inspects and can rewrite HTTP(S) content at the application layer (policy
DSL, per-host allow/deny, credential injection at egress); a gVisor `Netstack`
boundary would instead be able to give a **pre-effect, kernel-adjacent**
refusal of any *non-HTTP* egress attempt that bypasses the proxy entirely —
something the proxy alone cannot do, because it depends on the agent process
honoring `HTTP_PROXY`/`HTTPS_PROXY` and trusting the injected CA. Composing
the two (proxy for content-aware policy, gVisor Netstack for "nothing leaves
this sandbox except through the proxy, at all") is architecturally sound and
consistent with ADR 0035's explicit statement that mechanisms compose rather
than substitute. `hostinet` mode — passing network syscalls straight to the
host stack for performance — forfeits this specific advantage; see
[Threat boundary](#threat-boundary-and-host-kernel-exposure).

**No credential-broker or egress-broker crate currently exists in this
workspace to integrate against** — a `git grep` across `remote/main` for
`CredentialBroker`/`EgressBroker`-shaped types found none; the broker
concepts this ticket asks about are ADR-level design intent (ADR 0035's E5,
Epic AAASM-6159's "Authority" pillar) rather than a landed interface. This
document therefore cannot describe a concrete integration point beyond the
architectural one above, and says so rather than inventing an interface that
does not exist yet.

## Child-process behavior

Because the Sentry mediates every syscall for the entire process tree it
owns — not just the directly-launched process — `DescendantCoverage::ProcessTree`
is the architecturally expected answer for a gVisor backend, in contrast to
mechanisms that require explicit per-process opt-in to inherit restrictions.
This would be a genuine, measurable improvement over any shipped backend
whose descendant coverage defaults to `Unmeasured`
(`CapabilityReport::new`'s documented default, `aa-isolation/src/capability.rs:399-403`)
purely because nobody has yet instrumented it — **but it is still a claim
that needs a positive control** (spawn a forking, `exec`-ing subtree inside
`runsc` and confirm a policy violation from a grandchild is refused) before
it can be reported as anything stronger than `Unmeasured` on this axis for
this codebase's specific launch path.

## Resource controls

`runsc` integrates with the host's cgroups (v1 and v2) for the sandbox
process as a whole. Per-application resource accounting *inside* the Sentry
(distinguishing resource use between multiple processes sharing one sandbox)
has historically been coarser than native per-process cgroup accounting —
`runsc` has added nested-cgroup support over successive releases, but the
current fidelity on the kernel version this fleet would actually run is
**unmeasured**. `aa-isolation::CapabilityDomain::Resource` (numeric ceilings:
memory, CPU, process count, wall clock, file size, open descriptors,
`aa-isolation/src/capability.rs:62-64`) would need a real host measurement
per ceiling, not an assumption that "cgroups exist" implies all nine
sub-ceilings are enforced identically.

## Transaction support

**No, and this codebase would need to build its own regardless.** gVisor
uses an internal overlay (a writable tmpfs/overlay layer over a read-only
lower layer) to implement standard OCI container writable-layer semantics —
this is plumbing for *gVisor's own* filesystem virtualization, not a
general-purpose commit/discard primitive exposed to a caller. It has no API
shaped like "stage these mutations, then let the supervisor decide whether to
commit or discard them," which is what Epic AAASM-6159's transactional
pillar and the (not-yet-built, per this session's `git grep`) AAASM-6162
transactional-workspace design need. A gVisor backend gets, for free, the
same kind of isolated-scratch-writable-layer behavior any OCI container
runtime gets — it does not get the AASM-specific commit/discard/approve
semantics ADR 0035's "Transaction" pillar describes. Concretely: this
codebase would still need to build (or adopt, if one already exists
elsewhere in the workspace by the time AAASM-6162 lands) its own COW
workspace layer — most plausibly as a host-side overlay or snapshot
constructed *before* handing the prepared root to whichever backend is
selected — and a gVisor backend would consume that layer the same way any
other backend would, not replace the need for it.

## Broker integration

Covered under [Network integration](#network-integration) above for egress.
For **credential** brokerage specifically: gVisor has no native concept of
"inject this credential at the moment of use rather than as an ambient
environment variable" — that is entirely an AASM-side design (ADR 0035's E5,
`Credential` capability domain, `aa-isolation/src/capability.rs:59-61`,
already scoped as *"the authority the child inherits: environment secrets,
tokens, open descriptors and sockets that carry credentials"*). A gVisor
backend would receive whatever `child_environment` the launch plan
constructs, the same way `aa-isolation-native`, `aa-isolation-sandlock`, and
`aa-isolation-macos-vm` all do today (per the `IsolationBackend` doc
comment's AAASM-5942 note on not deriving `Debug` on structs holding that
map, `aa-isolation/src/backend.rs:264-276`) — gVisor changes nothing about
*how* a credential reaches the child, only how thoroughly the resulting
process tree is confined once it has one.

## Attestation/evidence ability

This is the one axis where gVisor may offer something no shipped backend in
this workspace has: **AAASM-6029 found that no shipped backend — native,
Sandlock, or the macOS VM — produces per-decision (`EvidenceKind::Decision`)
evidence today**, and identified the missing piece as entirely mechanism-side,
not contract-side (`evidence()` is already called at the right point;
`EvidenceKind::Decision` and the promotion path to
`ClaimTerm::DeniedBeforeExecution` already exist and are already tested).

gVisor ships an internal tracing/auditing framework (`seccheck` — a points-
and-sinks system the Sentry can be configured to emit structured events
through, covering syscall entry/exit and other Sentry-internal events) that
is architecturally positioned to be exactly the kind of per-decision producer
AAASM-6029 said was missing everywhere. **This is a documentation-derived
architectural observation, not a verified capability** — it has not been
exercised, and whether `seccheck`'s event shape can be mapped cleanly onto
`EvidenceKind::Decision` plus a `ClaimTerm` without additional Sentry-side
patching is unmeasured. If it holds up under a real prototype, it would be
the single most valuable reason to build this backend: it would let a gVisor
backend, and only a gVisor backend among current candidates, honestly report
`ClaimTerm::DeniedBeforeExecution` for a specific, named, per-action decision
rather than the network-of-shipped-controls-installed evidence every other
backend is limited to today. This should be the first thing a follow-up
prototype measures, precisely because AAASM-6029 already established how
much everything else depends on it.

## Packaging/distribution

`runsc` ships as a single statically-linked Go binary, historically in the
several-tens-of-megabytes range (recalled, not re-verified this session).
Distributing it alongside `aasm` would follow the same pattern
`aa-isolation-sandlock` already establishes for a vendored third-party
executable: pin an exact release, verify its checksum/digest (the same
digest-verification discipline `metadata/isolation-backends.json` already
applies to the pinned Sandlock release), and record provenance/SBOM data per
ADR 0035's stated supply-chain expectation for third-party backends. No new
distribution mechanism needs inventing; the existing one needs extending to
a second binary.

## Licensing/supply-chain

gVisor is **Apache License 2.0**, Google-maintained, and an active project —
this matches ADR 0035's explicitly stated backend-licensing preference
("permissive licenses (for example Apache-2.0/MIT/BSD)... explicit
third-party notices, provenance and SBOM data," ADR 0035 line 445) exactly.
No copyleft or unusual service-term concern applies. The remaining supply-
chain work is mechanical: `cargo deny`-equivalent tracking for the vendored
binary (not a Cargo dependency, so outside `cargo deny`'s own scope — this
would need the same manual pin-and-verify discipline `metadata/isolation-backends.json`
already applies to Sandlock, not a new tooling investment).

## Platform restrictions

**Linux only.** `runsc` requires a Linux host kernel (for `ptrace`, seccomp-
BPF, or KVM, depending on platform mode). On the existing macOS developer
path, `aa-isolation-macos-vm` already runs the *native* Linux isolation
backend inside a Linux guest reached over Virtualization.framework
(`PlatformBoundary::GuestKernel`). A gVisor backend would only ever be
reachable **nested inside that same guest** — it cannot become a macOS-native
backend, and stacking it inside the VM guest adds a second interception layer
(guest-kernel boundary, then userspace-kernel boundary within the guest) for
whatever additional syscall-mediation gVisor adds beyond what the guest's own
native/Sandlock backend already provides at the VM boundary. That is very
likely **not** where gVisor's marginal value lives for this product: on
macOS, the VM boundary is already the stronger, hardware-backed isolation
layer, and gVisor's real product niche is the deployment surface that has no
VM boundary at all — **managed Linux hosts/CI/server-side execution**, where
today's alternative is the weaker `SharedHostKernel` native/Sandlock
backends. This reframes the question the ticket implicitly poses ("is gVisor
better than the macOS VM backend?") into the one that actually matters for
this product: **is gVisor better than `aa-isolation-native`/`aa-isolation-sandlock`
on managed Linux, for workloads that need real POSIX/fork/toolchain support
WASM cannot give them?** — and the architectural answer to that narrower
question is plausibly yes, pending the measurements this document could not
make.

## Maintenance burden

gVisor is an actively developed, Google-maintained OSS project with frequent
releases and an evolving syscall-compatibility surface — the compatibility
list in this document will drift and must be re-verified against whatever
release is actually pinned before any claim ships, exactly as AAASM-6029
flagged for the Sandlock CLI-flag discrepancy it found (documented flags did
not match the AASM-emitted ones; presumed aliases, not verified). Concretely,
adding a fourth backend (`native`, `sandlock`, `macos-vm`, and now `gvisor`)
multiplies the combinatorial cost of the adversarial-conformance suite
[AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532)
already runs per backend, and adds a second Linux-only CI lane alongside
Sandlock's. This is a real, ongoing cost that should be weighed against the
attestation-evidence upside above, not treated as free because the licensing
and integration-pattern questions are both already answered favorably.

## gVisor versus the existing WASM/WASI backend (AAASM-1965)

This is the real product decision this spike serves, and the honest finding
is that **the two are not actually competing for the same boundary**, which
changes the shape of the comparison the ticket asks for.

`aa-sandbox` (AAASM-1965, Done) sandboxes **individual WASM-marked tool
executions** — a compiled WASI module, with wasmtime's fuel-based CPU budget
and memory-store limit giving strong, cheap, portable (Linux **and** macOS,
no root required) confinement for exactly the tool calls that can be compiled
to WASM. ADR 0035 is explicit that this is a *different boundary* from
whole-agent process isolation and the two "must never share a name or claim
merely because both use the word 'sandbox'." `aa-isolation` (this ticket's
actual target) confines the **whole agent process tree** — arbitrary native
binaries, `fork`/`exec`, real compilers, `git`, package managers, shell
scripts — none of which can run inside a WASI module at all. AAASM-1965's own
ticket history says so explicitly: WASM was chosen *first* precisely because
it does not require root and is portable across Linux and macOS dev
machines, and its own "Design choice point" section names gVisor as the
correct fallback the day WASM turns out insufficient for "actual code-exec
tools (e.g. tools that need POSIX `fork()`)" — which is exactly AAASM-6168's
premise.

So gVisor's marginal value is not "stronger than WASM for the same job" — it
is **capable of a job WASM structurally cannot do at all** (run arbitrary
native binaries, forked toolchains, real compilers), at a materially
narrower host-kernel attack surface than the alternative that *can* do that
job today (`aa-isolation-native`'s Landlock/seccomp on a shared kernel). The
discriminating question for AAASM-6167's planner is therefore not "WASM or
gVisor" — a coding agent's workload will route some steps to WASM-marked
tools (where compilable) and others to whole-agent execution (where it is
not), and both boundaries are needed simultaneously, composed, not chosen
between. gVisor's comparison set is `aa-isolation-native`/`aa-isolation-sandlock`
(both `SharedHostKernel`), not `aa-sandbox`. Framed that way: gVisor is worth
building **if and only if** a workload needs real POSIX/fork/native-toolchain
support (ruling out WASM) *and* the operator's risk tolerance requires
stronger-than-`SharedHostKernel` mediation for it (ruling out
native/Sandlock) *and* the deployment target is Linux without an existing VM
boundary (ruling out the macOS path, where the VM boundary already exceeds
what gVisor alone adds). That is a real, non-empty niche — managed Linux
CI/server execution of arbitrary coding-agent tool invocations — but it is a
narrower niche than "gVisor replaces WASM," and this document does not
recommend rebuilding or displacing AAASM-1965's WASM sandbox in any way.

## Conclusion — GO / CONDITIONAL GO / NO-GO

**CONDITIONAL GO.**

**What is not in dispute, from evidence gathered above:**

- gVisor fills a real, currently-unaddressed niche in this product's own
  architecture: whole-agent POSIX/fork/native-toolchain execution with a
  materially narrower host-kernel attack surface than the shared-kernel
  backends this repo already ships, for the Linux-without-a-VM-boundary
  deployment surface specifically.
- The integration shape is low-risk relative to inventing something new:
  drive `runsc` as an external OCI-style executable, the same pattern
  `aa-isolation-sandlock` already proves works inside this contract.
- Licensing (Apache 2.0) and the `PlatformBoundary::UserspaceKernel`
  vocabulary slot are already exactly right — no ADR amendment, no new enum
  variant, no product/legal escalation needed to start a prototype.
- It does not compete with or displace the existing WASM/WASI backend; the
  two solve different problems and the campaign should not treat this as an
  either/or.
- It may be the first backend in this workspace capable of closing
  AAASM-6029's per-decision evidence gap, via gVisor's `seccheck` framework —
  the single highest-value reason to prototype it, if that framework maps
  cleanly onto `EvidenceKind::Decision`.

**Why not a plain GO:**

- Every number in this document (startup cost, steady-state overhead,
  filesystem/network compatibility with a real coding-agent workload,
  resource-control fidelity, and — most importantly — whether `seccheck`
  actually produces `EvidenceKind::Decision`-shaped evidence) is
  documentation-derived or architectural, not measured. AAASM-6168's own
  acceptance criteria require measurement this pass explicitly did not
  attempt, per this pass's docs-only instructions.
- The macOS story is a net-negative framing if oversold: gVisor nested inside
  the existing VM guest is not a win over the VM boundary alone, and any
  follow-up must not imply gVisor helps macOS users.
- Building a fourth backend adds real, ongoing adversarial-conformance and
  CI-maintenance cost (AAASM-5532's per-backend multiplier) that has not been
  weighed against a concrete customer/product requirement — only an
  architectural opportunity.

**What "Conditional" means concretely — the follow-up this document
recommends:**

1. Open a scoped, Linux-hosted prototype ticket (a **real vertical slice**,
   satisfying the acceptance criteria this document deferred) that:
   - Runs a deterministic representative coding-agent workload (repository
     clone, dependency install, compiler invocation, at least one forked
     subprocess) through `runsc` and reports measured startup and
     steady-state overhead against `aa-isolation-native` on the same host.
   - Attempts a negative control demonstrating at least one prohibited side
     effect is actually refused (e.g., an out-of-scope filesystem write, or
     a non-proxied egress attempt under a `Netstack`-only network
     configuration) — the ticket's own explicitly required negative control.
   - Spikes `seccheck` specifically against `EvidenceKind::Decision`, since
     that is the one differentiator worth the rest of the investment.
   - Measures cgroup/resource-ceiling fidelity for at least the `Resource`
     domain's CPU and memory sub-ceilings.
2. Do not change any auto-selection default as part of that follow-up. Feed
   its `BackendCapabilities` output to AAASM-6167's property-based planner as
   one more evaluable candidate, exactly as that ticket's design already
   anticipates ("Planner can include existing WASM and future backend
   candidates without special-case CLI branching").
3. If the prototype's measured compatibility or overhead numbers
   contradict the architectural expectations in this document, this
   document's verdict is superseded by the prototype's — not the reverse.
