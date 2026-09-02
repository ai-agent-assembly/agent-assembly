# AAASM-5534 — host-wide mediation feasibility, re-baselined

What is left of AAASM-5534's original research programme once it is measured
against the code and ratified decisions that landed after the ticket was
written.

- **Ticket:** [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534)
  (Spike) · **Epic:** [AAASM-5526](https://lightning-dust-mite.atlassian.net/browse/AAASM-5526)
  — Host-wide capability mediation and truthful governance guarantees
- **Ticket written:** 2026-08-04 · **Re-baselined:** 2026-09-02
- **Compiled against** `remote/main` at `2bcccfc82`
- **Sibling artifact:** [`AAASM-5527-capability-coverage-matrix-and-threat-model.md`](AAASM-5527-capability-coverage-matrix-and-threat-model.md)

## Why this file exists

AAASM-5534 was chartered on 2026-08-04, and its framing assumes a starting
position that no longer holds. In the ticket's own words, *"SDK and proxy
enforcement cannot by themselves create a non-bypassable boundary"*, and
reaching one therefore required a feasibility study of platform mechanisms
AASM had not yet built.

Between then and now, Epic [AAASM-5702](https://lightning-dust-mite.atlassian.net/browse/AAASM-5702)
(execution isolation, Done) and Epic [AAASM-5811](https://lightning-dust-mite.atlassian.net/browse/AAASM-5811)
(macOS-hosted Linux isolation MVP, Done) shipped a capability-negotiated,
pre-effect host boundary with three backends, a ratified ADR, a benchmark
record, CI lanes and a hardware-qualification report. Most of 5534's research
questions now have measured in-tree answers rather than open ones, and a few
of its deliverables have become inappropriate rather than merely answered.

Running the spike as written would re-derive decisions that are already
ratified and would risk producing a second, competing platform matrix beside
[Core ADR 0033 §5.3](../docs/src/adr/0033-canonical-governance-and-enforcement-architecture.md#53-the-verified-platform-matrix) —
exactly the source-of-truth drift [Core ADR 0034](../docs/src/adr/0034-one-product-truth-and-cross-repository-documentation-governance.md)
exists to prevent. This artifact re-baselines the ticket instead.

## Why this file lives here

This is an evidence artifact, not book content — the same placement decision
[AAASM-5527](AAASM-5527-capability-coverage-matrix-and-threat-model.md) and
[AAASM-5528](AAASM-5528-public-claim-inventory.md) already made. A page under
`docs/src/` is unreachable unless registered in `docs/src/SUMMARY.md`, and a
point-in-time re-baseline is not living operator prose.

It is deliberately **not** a new ADR. Every durable decision this artifact
reports is already recorded in Core ADR 0033 or Core ADR 0035; a new ADR
restating them would create a second citable source for the platform matrix.
Where this re-baseline concludes that a ratified record should change, it says
so as a recommendation for an **amendment to the existing ADR** — the pattern
Core ADR 0035 already uses three times (AAASM-5751, AAASM-5801, AAASM-5808) —
and leaves the decision to the Epic owner.

## Method

Every classification below is grounded in a file read at `2bcccfc82`, not in
the ticket's own assumptions. Sources used:

| Source | What it settles |
|---|---|
| [Core ADR 0033](../docs/src/adr/0033-canonical-governance-and-enforcement-architecture.md) §5.1–§5.3, §6, §7, *Explicitly forbidden designs* | The canonical six-element model, what the Linux eBPF programs actually do, the verified platform matrix, the claim vocabulary |
| [Core ADR 0035](../docs/src/adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md) + its three amendments | The execution-isolation contract, the threat model, backends, what policy deliberately cannot express, `--isolation auto`'s selection algorithm |
| [`docs/src/security/execution-isolation.md`](../docs/src/security/execution-isolation.md) | The operator-facing support matrix, runtime prerequisites, per-backend capability table, benchmark summary |
| [`docs/src/devtools/limitations.md`](../docs/src/devtools/limitations.md) § *Hooks are not registered* | Why `PreToolUse` is deliberately unwired (AAASM-5646, Done) |
| `aa-isolation/src/lib.rs`, `descendant.rs`, `evidence.rs`, `plan.rs` | The negotiation/evidence contract: `negotiate`, `PlanRefusal`, `BackendCapabilities`, `EnforcementEvidence::supports_prevention_claim`, `DescendantCoverage` |
| `aa-cli/src/commands/run.rs` (`:1529`, `auto_select` `:1656`) | What `--isolation auto` and `--isolation process` actually select today |
| `aa-devtool-saas/src/lib.rs` | The SaaS adapter's `GovernanceLevel::L1Observe` ceiling |
| [`verification-report-AAASM-5811-hardware-qualification.md`](verification-report-AAASM-5811-hardware-qualification.md), `qa/golden-journeys.yaml` J64 | The macOS evidence grade — real Apple Silicon hardware, manual, not CI |
| `aa-integration-tests/tests/adversarial_isolation_launch.rs` | Which of AAASM-5532's seventeen attack classes are measured (three) |
| `.github/workflows/ci.yml` jobs `isolation-backend-linux` (`:3100`), `isolation-backend-native-linux` (`:3294`), `isolation-benchmark-*`, `isolation-dogfood-scenarios` | Which isolation lanes CI actually runs |

Windows was verified rather than inherited. Core ADR 0033 §5.3's dispositive claim
is that `windows_sys` is declared in no workspace manifest, so the stray
`#[cfg(windows)]` blocks cannot compile. Re-checked at `2bcccfc82`:
`git grep -c windows remote/main -- '*Cargo.toml'` returns no match (exit 1),
against a positive control (`libc`) that returns matches in five manifests, so
the empty result is a real absence and not a broken query.

## Classification legend

| Term | Meaning |
|---|---|
| **Implemented** | The question has a shipped, evidenced answer in-tree; nothing left to study |
| **Superseded** | A different mechanism or decision answered it, so the question as framed no longer applies |
| **Partially implemented** | Answered for part of its stated surface; a named residual remains |
| **Still unresolved** | Genuinely open and architecturally meaningful |
| **No longer appropriate** | Conflicts with current product direction; should not be pursued as chartered |

## Re-baseline: Linux

| Original topic | Classification | Evidence |
|---|---|---|
| seccomp-BPF, Landlock | **Implemented** | `aa-isolation-native` composes Landlock (filesystem) + seccomp-bpf (syscall) — Core ADR 0035's AAASM-5801 amendment. Floor stated plainly: Landlock ABI v3 / Linux 6.2, seccomp x86_64-only (`aa-isolation-native/src/rules.rs`). CI lane `isolation-backend-native-linux` |
| eBPF LSM (`bpf_lsm`) | **Still unresolved — and explicitly not attempted** | Core ADR 0033 §5.1: no `bpf_lsm` program, `SEC("lsm/…")` hook or `bpf_override_return` call exists in the tree, and `aa-ebpf-probes/src/syscall_guard.rs:55-60` says so in its own words. Superseded in *purpose* by the seccomp path above, which reaches the pre-effect denial `bpf_lsm` was wanted for |
| namespaces, cgroups | **Superseded** | Not an AASM mechanism question any more. Core ADR 0035 decision 2 puts mechanism choice inside a backend; Sandlock supplies `ProcessCreation`/`Resource`/`Ipc` coverage externally and AASM-native supplies none. Which primitive a backend uses is its own business, reported as capability domains |
| nftables | **Superseded** | Network egress is E3 transport mediation (`aa-proxy`), not a host firewall. Sandlock reports `NetworkEgress` supported; AASM-native reports it `Unsupported`. No host packet-filter integration is planned or needed for the domains the contract defines |
| Container runtime controls | **No longer appropriate** | Repo policy: self-hosted deployment is out of scope product-wide. See [Containers and VMs](#re-baseline-containers-and-vms) |
| Synchronous deny vs. observe/kill-after | **Implemented — as a type-level invariant, not a study** | Core ADR 0033 §6 fixes the vocabulary; `aa-isolation` enforces it structurally: `CapabilityReport::can_prevent` needs enforcement + pre-effect timing + synchronous semantics together, `negotiate` returns `Err(PlanRefusal)` before spawn when a `Required` prevention requirement meets an observe-only capability, and `EnforcementEvidence::supports_prevention_claim` ignores `Configured`/`Installed` records entirely. The eBPF syscall guard's asynchronous `SIGKILL` is `Detected`, never *denied before execution* |
| Process-tree propagation | **Implemented** | `DescendantCoverage` is reported per capability; `DescendantCoverage::Unmeasured` exists so "nobody looked" cannot read as coverage, and `negotiate` refuses a `DescendantRequirement::ProcessTree` against anything else (`aa-isolation/src/descendant.rs`). The governance half — a sub-agent asking for *better* terms — is `authority_widening`, with `AuthorityWidening::{LineageBroken,RequirementDropped,IntentWeakened,PostureWeakened,…}`. Grandchild confinement is one of the five hardware-qualified macOS scenarios |
| PID reuse, eBPF map capacity, privileged loader | **Partially implemented** | Privileged loader: decided — `aa-ebpf-loaderd` is the sole `CAP_BPF` holder, `aa-runtime` holds none (Core ADR 0033 §5.2). PID reuse and map capacity remain unstudied, but they are properties of the *observation* layer, not of the isolation boundary, so they no longer gate a mediation decision |
| gVisor, Kata, Firecracker | **Superseded** | The pluggable `IsolationBackend` contract turned "which isolation substrate" from an architecture question into an implementation choice behind a stable contract. Core ADR 0035 *Alternatives considered* already rejected requiring a microVM for every launch, and `aasm-macos-vm` demonstrates the guest-VM route where it is the only option. Adding one of these is a backend proposal, not a feasibility study |

## Re-baseline: macOS

| Original topic | Classification | Evidence |
|---|---|---|
| Endpoint Security, Network Extension | **Implemented as a decided non-goal** | Core ADR 0033 §5.3 records them as an **explicit non-goal**, asserted in product docs and pinned by a test asserting the literal limitation string (`aa-cli/src/commands/integrations/model.rs:1200,1204`). Core ADR 0035 *Reconsideration trigger 4* names them and **has not fired**. DTrace was considered and rejected as observability-only |
| Sandbox profiles | **Superseded** | AAASM-5810/5811 chose a different boundary shape: a confined Linux guest under Virtualization.framework, reusing `aa-isolation-native` inside the guest, rather than an in-process App Sandbox profile on the host |
| launchd / MDM | **Partially implemented** | The macOS root-owned managed-settings write is the **only** production producer of `EvidenceKind::HostAttested` and the only route by which Core ADR 0030's `HostEnforced` rung is reachable at all (`aa-devtool-claude-code/src/lifecycle.rs:556`). Whether the tool honours those keys at runtime is **Unmeasured** — the adapter's own docs call it *"the open half of AAASM-5298"* |
| Keychain / session constraints | **Implemented** | `aa-proxy` CA trust on macOS shells out to `security add-trusted-cert` and needs admin authorization; AAASM-5978 made this conditional via `AA_PROXY_SYSTEM_TRUST_INSTALL`, and the Claude Code managed launch sets `Never` and uses process-scoped `NODE_EXTRA_CA_CERTS` trust instead — so that path makes zero System Keychain calls |
| Entitlement, signing, distribution, user consent | **Implemented** | `com.apple.security.virtualization`, local ad-hoc codesign, no Apple provisioning grant needed at this trust level (AAASM-5840 pattern, hardware-qualification report). The released `aasm` binary cannot carry the entitlement, which is *why* the operator supplies helper/kernel/rootfs via `AA_ISOLATION_MACOS_VM_{HELPER,KERNEL,ROOTFS}`. Guest kernel and busybox are GPL-2.0-only, recorded in `metadata/isolation-backends.json`, shipped through no channel, and `scripts/check-backend-license-compliance.sh` fails the day one is |
| Local-first OSS vs. managed enterprise | **Implemented as a decision** | Local-first is the shipped route (operator-supplied artifacts, no bundled backend binary on any channel). Managed-enterprise deployment is out of scope product-wide |

**The macOS evidence grade must not be overstated.** `aasm-macos-vm` is
hardware-qualified on Apple Silicon by a *manual*, local run under
`--test-threads=1`, recorded in
[`verification-report-AAASM-5811-hardware-qualification.md`](verification-report-AAASM-5811-hardware-qualification.md)
and indexed as golden journey J64 — not by an automated gate. GitHub-hosted
macOS runners provide no nested virtualization. Intel/x86_64 is unqualified and
unclaimed.

## Re-baseline: Windows

| Original topic | Classification |
|---|---|
| AppContainer, WFP, Job Objects, WDAC/AppLocker, ETW, service isolation | **Still unresolved, and confirmed out of scope — No-Go** |
| Administrator/enterprise requirements, realistic distribution | **No longer appropriate to study** at current product direction |

**Confirmed, not assumed.** Three independent facts at `2bcccfc82`:

1. **No isolation backend targets Windows.** `--isolation process` and
   `--isolation auto` are *refused* (`Boundary::Refused`) on a Windows host,
   never silently downgraded to unconfined.
2. **No transport mediation either.** `aa-proxy`'s accept loop uses
   `tokio::signal::unix` unconditionally (`aa-proxy/src/proxy/mod.rs:296,298`),
   so the crate has no Windows build path.
3. **The stray `#[cfg(windows)]` blocks cannot compile.** `windows_sys` is
   referenced in `aa-cli/src/commands/dashboard/stop.rs` but is declared in no
   workspace manifest — re-verified this pass with a positive control, as
   described under [Method](#method).

No ETW, WFP or minifilter code exists. Nothing has changed since Core ADR 0033
§5.3 recorded this. **Recommendation: keep Windows out of scope**; a Windows
host adapter stays *research* until an implementation exists, and must be
labelled as such (Core ADR 0033 §6).

## Re-baseline: containers and VMs

| Original topic | Classification | Evidence |
|---|---|---|
| Default-deny egress, read-only filesystems, dropped capabilities, seccomp/AppArmor/SELinux | **Superseded** | These are mechanism realizations, and Core ADR 0035 decision 2 puts mechanism inside a backend while AASM owns the execution contract. An operator states isolation *properties* (`none`/`auto`/`process`) and capability-domain requirements; the backend realizes them. Re-studying container-runtime flags would re-open a decision the contract already made |
| Metadata-service protection | **Still unresolved**, but low-value at current direction | Sandlock covers `NetworkEgress`; AASM-native does not; the macOS guest has no network device at all. There is no cloud-metadata capability domain reachable through any shipped backend today |
| Credential brokering | **Partially implemented** | `aa-isolation/src/ambient.rs` + `descriptor.rs` model this: `CredentialPosture` splits *removed* from *could not be removed*, `EnvironmentPlanner` cannot place a kept compatibility exception in `removed`, and a non-empty `ambient_unremoved` means the run is not least-authority and every rendering must say so. A capability-token/broker protocol is **not** built — and nothing currently requires one |
| Container-owner vs. host-owner boundary | **No longer appropriate** | This question only pays off for a deployment model this product does not ship. Repo policy: self-hosted deployment is out of scope product-wide — no Helm/Terraform/Kubernetes/air-gapped work |

**Ticket AC #6 is unsatisfiable as written.** The acceptance criterion *"at
least one feasible reference architecture is proposed for managed
Linux/container deployment"* asks for the deliverable that current product
policy forbids proposing. It should be struck rather than quietly satisfied.

## Re-baseline: opaque SaaS agents

| Original topic | Classification | Evidence |
|---|---|---|
| What can be proven via provider-native config, webhooks, model gateways, audit APIs | **Implemented** | `aa-devtool-saas` implements `DevToolAdapter` for Claude.ai, ChatGPT and Cursor cloud: per-provider HMAC-SHA256 webhook signature verification (`signature::verify`), per-provider body parsers (`parser::parse`), a normalized `SaasAuditEvent`, advisory MCP allowlists, and per-provider governance overlays. Events map into the existing `aa_devtool_contract::AuditEntry` pipeline via `aa-api::routes::devtools::saas_webhook`. HMAC secrets are held only as opaque Vault-style reference strings |
| What must stay `Configured` / `Detected` / `Unmeasured` rather than `HostConstrained` | **Implemented — as a construction, not a guideline** | The adapter is **capped at `GovernanceLevel::L1Observe`** in the crate itself: *"Because these agents run in opaque SaaS environments, the adapter is capped at `L1Observe`: it can receive signed audit webhooks and apply advisory MCP allowlists, but cannot perform in-process enforcement (L2) or native SDK integration (L3)."* The ceiling is enforced by the type, so a SaaS row cannot reach a host-constrained claim by configuration |

**Recommendation: keep opaque SaaS mediation out of scope — No-Go.** Where AASM
does not own the host, the honest ceiling is signed observation. This is not a
gap to close; it is a boundary already stated correctly.

## Re-baseline: required trust assumptions

| Assumption | Classification | Evidence |
|---|---|---|
| Agent untrusted, host operator trusted | **Implemented** | Core ADR 0035 threat model states it as a deliberate non-goal: execution isolation does not protect a machine from its own root/administrator account, and an operator removing AASM is not a bypass of anything claimed |
| Local user and agent share identity | **Partially implemented** | Two named, measured residuals: `/proc/<pid>/environ` remains readable, so an empty-then-delegated child environment is not by itself a credential boundary ([AAASM-5785](https://lightning-dust-mite.atlassian.net/browse/AAASM-5785)); and `aasm run` deliberately passes the agent's own upstream credentials through — only proxy variables are stripped from the child environment — because the launched tool needs them to function |
| User has administrator/root | **Implemented** | Same non-goal as above; stated plainly rather than caveated away |
| Enterprise manages the device | **Partially implemented** | The macOS managed-settings route is the one reachable `HostEnforced` path, and its runtime honouring is Unmeasured. No MDM/Windows-domain story exists, and none is in scope |
| Third-party SaaS controls the host | **Implemented** | The `L1Observe` ceiling above |

## Re-baseline: the ticket's own deliverables

| Deliverable | Classification | Where it is, or why not |
|---|---|---|
| Platform comparison matrix | **Implemented** | Core ADR 0033 §5.3 (E3/E4 per platform) and `docs/src/security/execution-isolation.md`'s support + per-backend capability tables. A third matrix should not be created |
| Reference-monitor architecture proposal | **No longer appropriate** | A separate reference monitor would be a new host interception mechanism sitting beside the one already negotiated by `aasm run`. Core ADR 0033 forbids re-introducing an interception-layer framing, and Core ADR 0035 already assigns E2/E4/E5/E6 to the isolation path. See [Why not a new mediation layer](#why-a-new-host-wide-pretooluse-mediation-layer-is-not-the-recommendation) |
| Credential-broker / capability-token design implications | **Partially implemented** | Modelled procedurally (`ambient.rs`, `descriptor.rs`, `CredentialPosture`, AAASM-5709) rather than as a token protocol. No consumer requires a token protocol today |
| Required privileges, install UX, performance costs | **Implemented** | Runtime-prerequisite tables per backend (Linux, AASM-native, macOS VM) with the exact diagnostic and fix for each failure; AAASM-5805's three-arm benchmark grades P1–P7 with admissibility rules, committed in `benchmarks/isolation/METHODOLOGY.md`; licensing/distribution stated per channel |
| Failure and recovery model | **Implemented** | Refuse-before-spawn with no fallback; a launch that asked for a boundary never runs unconfined. `Degraded` always carries planned *and* achieved as separate fields. `negotiate`'s refusal is the `Err` arm, so a refused launch is not representable as an `EnforcementPlan` |
| Prototype recommendations for the highest-value boundary | **Superseded** | The prototypes were built rather than recommended: Epic AAASM-5702 (Linux) and Epic AAASM-5811 (macOS), both Done |
| Go / Conditional Go / No-Go per platform | **Delivered here** | See [Verdicts](#verdicts) |
| Follow-up implementation Epics with phased roadmap | **Superseded** | Epics 5702 and 5811 already exist and are Done. The residual work is the gap list below, most of which is already ticketed |

### The ticket's acceptance criteria

Seven of nine are satisfied by artifacts that already exist (separate
per-platform conclusions; pre-execution vs. observe/kill distinguished;
root/admin limits stated; credential ownership and ambient authority modelled;
performance/packaging/signing/entitlement estimated; macOS given an
evidence-backed conclusion rather than assumed parity; a precise product claim
with a verification plan). Two do not survive re-baselining:

- **AC 6** (*reference architecture for managed Linux/container deployment*) —
  **no longer appropriate**, per the product-wide self-hosted-deployment
  non-goal.
- **AC 9** (*follow-up tickets produced for approved prototypes*) —
  **superseded**; the prototypes shipped under Epics 5702 and 5811.

## Why a new host-wide `PreToolUse` mediation layer is not the recommendation

The obvious reading of 5534 is "build the reference monitor" — most concretely,
wire a `PreToolUse` hook so shell and file tool calls are adjudicated before
they run. Three findings argue against chartering that.

**1. It is already a decided `No`, with reasons that are design questions, not
oversights.** [AAASM-5646](https://lightning-dust-mite.atlassian.net/browse/AAASM-5646)
is Done, and `docs/src/devtools/limitations.md` records the reasoning: the
decision function a hook would need — `handle_policy_query` — is private to a
running `aa-runtime` process and reached only over gRPC, with registry lineage,
`op_control` state and audit-write side effects a short-lived hook subprocess
has none of; `allowManagedHooksOnly: strict` makes a locally-written hook inert
under exactly the profile that most needs it, so the real change is a
root-owned managed-document write with its own review surface; and no test pins
the exit-code contract, so registering a hook now would convert a *documented
absence* into an *undocumented, untested bypass* — a worse state.

**2. The pre-effect mechanism for that same problem already exists, and it is
not the hook.** `aasm run --isolation` establishes a kernel-enforced boundary
around the launched agent's whole native process tree and every descendant, and
it does so **before the untrusted process starts** — Core ADR 0033's E2 + E4 +
E5 + E6. A `GovernanceAction::ProcessExec` deny rule against
`Capability::TerminalExec` that the Claude Code integration cannot generate in
time *is* enforceable today, by a filesystem/syscall boundary the process
cannot step outside of,
without a per-tool-call adjudication round trip. That is a different and
stronger shape than a hook: it does not depend on the tool cooperating, on a
hook's exit code, or on any settings file being honoured at runtime.

**3. `aa-proxy` and `aa-ebpf` are complements, not the answer — and must not be
described as one.** It would be convenient to close 5534 with "host-wide
mediation is already handled by the proxy and eBPF layers." That claim is
false, and it is false in exactly the way Core ADR 0033's forbidden designs #2
and #4 name:

- `aa-proxy` is **E3 transport mediation** — outbound HTTPS only, HTTP/1.1 on
  MitM'd hosts, `llm_only` defaulting to `true` so only the built-in LLM hosts
  are decrypted, and no Windows build path. It never sees a local shell command
  or a file write.
- `aa-ebpf` is **observation**. Every program is observe-only except
  `syscall_guard`, which is off unless `AA_EBPF_CONFINE_PID` is set, kills
  **asynchronously** with `bpf_send_signal(SIGKILL)` after the offending
  syscall has already executed, carries a documented load-time window, and
  cannot block a `fork`. No eBPF signal participates in any allow/deny
  decision. That is `Detected`, never *denied before execution*.

So the correct conclusion is not "already solved by proxy + eBPF." It is: **the
boundary 5534 was chartered to find was built, by a different mechanism than
the ticket anticipated** — capability-negotiated execution isolation, not a
reference monitor or a tool-call hook — and adding a second host mediation
mechanism now would duplicate E4 rather than close a gap.

## Remaining architectural gaps

Only items that are genuinely open, architectural, and not a re-litigation of a
ratified decision.

### G1 — No shipped backend can support a per-action prevention claim (the headline gap)

`supports_prevention_claim` is false for every capability domain, on every
backend AASM ships, always. The confinement is real — the kernel refuses the
confined process's own syscall and the error returns to *that* process — but no
mechanism delivers a per-decision record back to the AASM supervisor. So the
product can truthfully say a control was *configured*, that it was *installed*
before the program started, and that the program *ran*, and it cannot say the
control *decided* anything about a specific action.

Reaching a per-action *denied before execution* claim needs a per-decision
record from the mechanism, which no shipped backend emits and which the
`IsolationBackend` contract has no channel for. **This is the one remaining
gap in this list that is architectural rather than incremental**, and it is not
currently ticketed. It is also the gap that most constrains what the product
may claim.

### G2 — No single backend covers the domain union, and a two-domain policy can be unsatisfiable

From the published per-backend capability table: Sandlock reports `Syscall`
**Unsupported**; AASM-native reports `NetworkEgress`, `ProcessCreation`,
`Resource`, `Ipc` and `Credential` **Unsupported**; the macOS guest has no
network device at all and sends `syscall_filter: None` on every launch.
`--isolation auto` walks `[sandlock, aasm-native, aasm-macos-vm]` and selects
the first candidate whose `plan()` returns `Ok` (`aa-cli/src/commands/run.rs`
`auto_select`). It follows that a policy requiring prevention for **both**
`Syscall` and `NetworkEgress` has no eligible candidate in the shipped set, and
`auto` refuses naming all three. The refusal is honest and fail-closed — this
is not a correctness bug — but the *capability* gap is real and closing it
means a backend that covers the union, not a selection change.

### G3 — Four of nine capability domains cannot be expressed in policy

`NameResolution`, `Ipc`, `Credential` and `Resource` report
`DomainCoverage::PolicyCannotExpress`. This is **already recorded as accepted,
measured risk** in Core ADR 0035's AAASM-5751 amendment, and for three of them
Sandlock can enforce something an operator has no way to ask for. Listed here
so the boundary picture is not missing a domain, **not** as a new decision —
the ADR's reasoning (speculative schema is a public contract that cannot be
withdrawn; a named gap can be closed at any time) stands.

### G4 — Architecture asymmetry on Linux

AASM-native's seccomp filter is a hand-built cBPF program against the x86_64
syscall table, so `Syscall` reports `Unsupported` on aarch64 while filesystem
domains keep working. Independently, the eBPF file-I/O kprobes are x86_64-only
(hardcoded `__x64_sys_*`), so aarch64 Linux gets no file-I/O observation. Two
different mechanisms, the same architecture cliff.

### G5 — macOS backend limits

No general toolchain inside the guest (AAASM-5849, partially addressed by
PR #2332's git/python3 layering, ticket still open); `Syscall` structurally
`Unsupported`; no network device, so network/metadata domains are *absent*
rather than measured-and-denied; guest kernel and rootfs unshipped and
GPL-2.0-only (AAASM-5840); one full guest boot per launch plus one more inside
`discover()`; and no CI lane exercises the host↔guest path, so this boundary is
qualified by hand on entitled Apple Silicon hardware.

### G6 — Adversarial conformance is at three of seventeen attack classes

[AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532)'s
harness measures three classes honestly and stubs none: managed-vs-unmanaged
launch, fail-closed on an unavailable backend, and interruption during a
managed launch. The classes that would actually exercise a *confinement*
boundary — fork/exec, detached and re-parented descendants, filesystem escape
via symlink/rename — are absent because they need a Linux-privileged lane to
have something to escape from, and the harness's own module doc says so rather
than reporting a hollow pass. Given that descendant confinement is one of the
isolation contract's load-bearing correctness properties, this is the highest-
value remaining verification work.

### G7 — The one reachable `HostEnforced` route rests on a file read-back

The macOS managed-settings write is the only production producer of
`EvidenceKind::HostAttested`, and whether the tool honours those keys at
runtime is Unmeasured. The rung is reachable; the evidence under it is a
read-back of a file, not observed enforcement.

## Verdicts

| Platform / deployment model | Verdict | Basis |
|---|---|---|
| **Linux (x86_64)** | **Go — already shipped** | Two backends, CI lanes, benchmark record. Remaining work is G1/G2/G6, not feasibility |
| **Linux (aarch64)** | **Conditional Go** | Filesystem confinement works; `Syscall` and eBPF file-I/O are absent (G4). Ship with the gap stated, as the docs already do |
| **macOS (Apple Silicon)** | **Conditional Go — already shipped** | Real hardware-qualified guest confinement with named limits (G5). Manual qualification, not CI |
| **macOS (Intel)** | **No-Go** | No build exists; not attempted; unclaimed |
| **Windows** | **No-Go — confirmed this pass** | No backend, no proxy build path, no `windows_sys` in any manifest, no ETW/WFP/minifilter code |
| **Containers / VMs (self-hosted)** | **No-Go as a product deliverable** | Self-hosted deployment is out of scope product-wide. A container substrate may still appear as a *backend* under the existing contract |
| **Opaque SaaS** | **No-Go for mediation; Go for signed observation** | `aa-devtool-saas` caps at `L1Observe` by construction |

## Scope fences

Three adjacent questions are **not** in this re-baseline and must not be
absorbed into 5534:

- **MCP transport mediation and real agent identity binding** —
  [AAASM-5533](https://lightning-dust-mite.atlassian.net/browse/AAASM-5533)
  (sibling spike, To Do), with
  [AAASM-5650](https://lightning-dust-mite.atlassian.net/browse/AAASM-5650)
  adjacent.
- **Capability-aware `--isolation auto` selection** —
  [AAASM-5808](https://lightning-dust-mite.atlassian.net/browse/AAASM-5808),
  Done; the algorithm is recorded as an Core ADR 0035 amendment.
- **The PreToolUse hook decision itself** —
  [AAASM-5646](https://lightning-dust-mite.atlassian.net/browse/AAASM-5646),
  Done; `limitations.md` states it does not wait on 5534.

## Recommendation for AAASM-5534

**Close as superseded, except for G1 and G6**, which should be carried by
tickets of their own rather than kept alive inside a spike whose framing no
longer matches the code.

Concretely:

1. **Strike AC 6 and AC 9** — the first conflicts with the self-hosted
   deployment non-goal, the second was satisfied by Epics 5702/5811 shipping.
2. **Accept this artifact as 5534's deliverable** for the platform matrix, the
   trust-assumption analysis, the privileges/UX/performance estimates, the
   failure/recovery model and the per-platform Go/No-Go.
3. **Open a new spike for G1** — whether any shipped or candidate backend can
   deliver a per-decision record to the supervisor, and what the
   `IsolationBackend` contract would need to carry it. This is the single
   remaining question that changes what the product may claim.
4. **Route G6 to AAASM-5532** rather than to a new ticket — the Linux-privileged
   adversarial lane is already that ticket's own stated acceptance criterion.
5. **Leave G3, G4, G5 and G7 where they are** — recorded in Core ADR 0035's
   amendment, in the docs' platform matrix, and in AAASM-5785/5814/5840/5849
   respectively. None needs a new decision.
6. **Do not open a reference-monitor or host-wide `PreToolUse` implementation
   Epic.** See [the section above](#why-a-new-host-wide-pretooluse-mediation-layer-is-not-the-recommendation).

Status transition is deliberately **not** performed by this artifact; it is the
Epic owner's call.

## Incidental findings — reported, not fixed

Two published statements were found to disagree with the code at `2bcccfc82`
while compiling this re-baseline. Both are outside 5534's scope and are
recorded here rather than changed, following the AAASM-5527 precedent.

### F1 — `execution-isolation.md` states that `--isolation auto` selects Sandlock unconditionally; it does not

`docs/src/security/execution-isolation.md:384` — *"`aasm run --isolation auto`
does not use that recommendation. Sandlock remains the default"* — and `:411` —
*"until it ships, `--isolation auto` selects Sandlock unconditionally"* — both
describe the pre-AAASM-5808 behaviour. AAASM-5808 is Done and ratified as an
Core ADR 0035 amendment (2026-08-21): `aa-cli/src/commands/run.rs:1529` routes
`IsolationIntent::Auto` to `auto_select` (`:1656`), which walks a candidate
list and selects by `plan()` eligibility. The page's own claim that
`isolation_backend`'s default "continues to select Sandlock" is true only for
`--isolation process`, not for `auto`.

**Impact:** an operator reading the current page will believe `--isolation auto`
under-selects, and may pin `--isolation-backend` unnecessarily. Suggested
disposition: a Bug under Epic 5526 to reconcile that section (and its heading,
*"Choosing between the two backends"*, on a page that opens by stating three
backends ship).

### F2 — Core ADR 0035's AAASM-5808 amendment names a two-candidate walk; the code walks three

The amendment states the candidate list is `[sandlock, aasm-native]`, Sandlock
first. `auto_select`'s `CANDIDATES` is a three-element array including
`aa_isolation_macos_vm::BACKEND_ID`. The behaviour is defensible — the macOS
backend is only reachable on a macOS host in the first place, and an
unavailable candidate is rejected with a recorded `ConsideredBackend` — but the
ratified text and the code do not say the same thing.

**Suggested disposition:** a small amendment correction to Core ADR 0035, or a Bug
alongside F1. Not fixed here: a spike should not edit a ratified ADR.
