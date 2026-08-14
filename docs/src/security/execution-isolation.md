# Execution isolation

`aasm run --isolation` establishes a kernel-enforced boundary around a
launched agent's **whole native process tree** — its own process and every
descendant it spawns — as a capability distinct from tool-call governance,
network mediation, or the WASM tool sandbox. This page is the mental model,
the threat boundary, the capability/evidence semantics, the platform/backend
support matrix, and the troubleshooting reference for that boundary.

**Product story in one line:** agent → `aasm run` → identity + policy →
execution plan → enforcement backend → evidence. Backend availability,
observation, and enforcement are three different facts, and this page keeps
them that way.

This page is normative alongside
[ADR 0035 (Agent Execution Isolation & Pluggable Enforcement Backends)](../adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md),
which remains the canonical decision record — read it for the full threat
model, the alternatives considered, and the reconsideration triggers. This
page occupies the operator-facing surface: what to run, what it means, and
what to expect on a host that does not (yet) support it.

## Mental model

Execution isolation is **not** a seventh interception layer and does not
replace or extend the SDK/proxy/eBPF mechanisms described in
[ADR 0033 (Canonical Governance & Enforcement Architecture)](../adr/0033-canonical-governance-and-enforcement-architecture.md).
It occupies four of ADR 0033's six elements:

| ADR 0033 element | What execution isolation contributes |
|---|---|
| **E2 · Managed Execution Checkpoints** | `aasm run` resolves the launch and its required capabilities *before* the untrusted process starts. |
| **E4 · Platform-Specific Host-Level Interception Adapters** | A concrete isolation backend realizes the OS-specific restrictions it actually supports — see the [support matrix](#platform-and-backend-support-matrix). |
| **E5 · Credential / Capability Boundary** | The launched process receives only the ambient authority and delegated capabilities its execution plan permits. |
| **E6 · Evidence & Protection-State Pipeline** | Requested, planned, achieved, and unmeasured controls are reported separately — backend availability is never evidence of enforcement by itself. |

A single AASM policy describes required isolation **properties** (a
backend-neutral class: `none`, `auto`, or `process` — see the
[`aasm run` CLI reference](../cli/run.md#isolation-intent---isolation)), never
a vendor or mechanism name. Which concrete backend realizes that policy is an
execution-plan fact, resolved on the host at launch time. This is what makes
the boundary **portable**: replacing or adding a backend does not require
rewriting policy.

## Not the WASM tool sandbox

[`aa-sandbox`](../cli/sandbox.md) and execution isolation are two different
boundaries around two different things, and must never share a name or a
claim merely because both use the word "sandbox":

| | `aa-sandbox` | Execution isolation (`aasm run --isolation`) |
|---|---|---|
| **What it confines** | One WASM-marked **tool call**, run under Wasmtime/WASI | The agent's **whole native process tree** — the launched program and every descendant it spawns |
| **Mechanism** | Userspace WASM runtime: preopened directories, instruction fuel, memory pages, wall-clock deadline | A host-level backend (currently [Sandlock](#platform-and-backend-support-matrix), Linux-only) confining a real OS process |
| **Where it runs** | Any platform Wasmtime supports | Only where a backend exists for the host — today, Linux only |
| **Invoked via** | `aasm sandbox run <module.wasm>`, or a tool marked for sandboxed execution inside the governed tool-call path | `aasm run --isolation auto\|process` |
| **ADR 0033 element** | Part of E2 (a WASM-marked tool call is itself a checkpoint) | E2 + E4 + E5 + E6, as above |

A native agent may call a WASM tool inside `aa-sandbox` while itself running
under execution isolation — that is **composition of two boundaries**, not
evidence that either one replaces the other (ADR 0035 §7).

## Threat model

Execution isolation's threat model (full text in
[ADR 0035 § Threat model](../adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md#threat-model))
adds the following to the [general threat model](threat-model.md):

- **The agent is adaptive and hostile.** It may enumerate files, environment,
  network routes, metadata endpoints, IPC, sockets, credentials, process state
  and alternate execution paths, and may spawn arbitrary descendants trying to
  escape or widen its own authority.
- **The host operator and the AASM supervisor are trusted.** This is a
  deliberate **non-goal**: execution isolation does not protect a machine from
  its own root/administrator account. A trusted operator can remove AASM,
  replace its binaries, change the kernel, modify a policy they are authorized
  to modify, or otherwise exercise administrator ownership of the machine, and
  none of that is a bypass of anything this boundary claims.
- **The trusted supervisor stays outside the confined process tree.** The AASM
  control/runtime process must not share the hostile process's security
  boundary in a way that would grant the child access to supervisor memory,
  privileged descriptors, or credentials simply because both participate in
  one launch.
- **Descendant inheritance is part of correctness, not an afterthought.** An
  agent that can escape merely by spawning a child has no meaningful process
  boundary. A backend is not considered capable of a process/filesystem/network
  restriction unless its semantics cover the descendant processes relevant to
  that restriction, or the limitation is explicitly surfaced in the
  capability report and evidence. Ordinary process creation must not widen OS
  capabilities; sub-agent identity may narrow at the governance layer, but
  never widens at the OS layer.
- **The absence of an event is not proof the agent did nothing.** An
  unsupported, bypassed, or uninstrumented path is reported per the claim
  vocabulary below — never inferred clean.

## Pre-effect denial vs. observe/detect

Execution isolation reuses [ADR 0033 §6's claim vocabulary](../adr/0033-canonical-governance-and-enforcement-architecture.md#6-claim-vocabulary--decision-timing-and-failure-posture-are-part-of-every-claim)
rather than inventing a parallel one. The distinction that matters most here:

| Term | What it means | What it does *not* mean |
|---|---|---|
| **Denied before execution** | A control refused the action before it took effect. The only term that claims prevention — it requires a refusal by a component sitting *before* the effect. | Not: an event was later found in a log. Not: the process exited non-zero. |
| **Observed** / **Detected** | An event reached the evidence pipeline, or a pattern of interest was found in it — *after* the fact. | Not prevention. An asynchronous kill after a syscall has already run is **Detected**, never *Denied before execution* — this is exactly the distinction ADR 0035 draws against the Linux eBPF syscall guard, which kills asynchronously and is explicitly **not** equivalent to a process sandbox. |
| **Unsupported** | No applicable mechanism exists on this host, backend, or backend version. | Not a soft "probably fine" — it is a stated gap. |
| **Degraded** | A planned control is configured but unavailable, so the achieved level is below the planned level, and posture explicitly permits proceeding. | Must always carry **both** the planned and achieved level — never presented as equivalently protected. |
| **Unmeasured** | Nothing inspected this action or payload. | The honest state for anything outside the boundary — never silently upgraded. |

**The single most important rule to get right:** `supports_prevention_claim`
is false for every capability domain, on every backend AASM ships today,
always. The confinement the shipped Sandlock backend enforces is real — the
kernel refuses the confined process's own syscall, and the denial is
delivered to *that* process as an error return — but the AASM supervisor has
no channel that reports the individual decision back to it. So the shipped
backend can truthfully say a control was **configured**, that it was
**installed** before the program started, and that the program **ran** — the
three grades that are honest — and it cannot say the control **decided**
anything about a specific action. Reaching a `Denied before execution` claim
per-action would need a per-decision record from the mechanism; until one
exists, AASM reports the absence rather than manufacturing a decision record
from "the program exited non-zero", which would be exactly the false
promotion this rule exists to prevent.

This does **not** mean execution isolation is weak — a policy that requires a
pre-effect denial and gets a backend that can only observe **refuses the
launch** rather than silently downgrading (see
[Requested vs. achieved](#requested-vs-achieved-the-report-shape) below). It
means the product's own claim about what happened to a *specific* action stays
scoped to what is actually evidenced.

## Requested vs. achieved: the report shape

Every `aasm run` — including `--isolation none` — produces an
`IsolationReport`, printed under `--- execution isolation ---` in
[`aasm run --dry-run`](../cli/run.md#dry-run-output) and available as
machine-readable `key=value` lines for scripting. The report is built from two
independent inputs that must never collapse into one number:

**1. What policy requested**, per capability domain
(`RequestedControl`, four states):

| State | Meaning |
|---|---|
| `Stated` | Policy stated a requirement for this domain — carries the intent, posture, descendant requirement, and scope. |
| `NotStated` | The policy schema has a node for this domain and this document left it unset. The remedy is to edit the policy — there is one to edit. |
| `PolicyCannotExpress` | The schema has **no node at all** that can express this domain. **Never read this as "no restriction required"** — it is the absence of a way to ask, not the presence of an answer. |
| `NotDerived` | No policy lowering was attached to this report at all, so nothing recorded whether anything was asked. |

**2. What the boundary will do or did**, per capability domain
(`ControlState`), including `Prevention` (with decision timing and descendant
coverage), observe-only states, and `Degraded` (which always carries both the
planned and the achieved level as separate fields, never merged).

The nine capability domains this contract covers: filesystem read, filesystem
write, network egress, name resolution, syscall, process creation, IPC,
credential, and resource ceilings. A single boolean `sandbox=true` or
`supported=true` is explicitly rejected by ADR 0035 as insufficient.

**A policy gap is not silence.** Where the policy schema simply has no node
for a domain (`PolicyCannotExpress`), the current accepted, measured gap
covers name resolution, IPC, credential, and resource — recorded as a real gap
in [ADR 0035's amendment](../adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md#what-deliberately-remains-unrepresentable),
not silently treated as "nothing to restrict". Filesystem path scope
(`filesystem:` in policy — see the [Policy YAML Reference](../policy-reference.md#filesystem))
is expressible as of AAASM-5751.

### The `/proc` caveat on credential isolation

The shipped backend starts the confined child's environment **empty** and adds
back only the names the launch explicitly delegated — a real control, reported
as `Partial` support with named limitations. **This is not by itself a
credential boundary while `/proc` is readable**: a confined child process's
environment can still be inspected via `/proc/<pid>/environ` by anything with
`/proc` read access on the host. Any claim this product makes about
credential/environment isolation must carry this caveat rather than silently
glossing over it (tracked as a known, non-blocking residual gap,
[AAASM-5785](https://lightning-dust-mite.atlassian.net/browse/AAASM-5785)).

## Platform and backend support matrix

**Only one execution-isolation backend ships today, and it is Linux-only.**

| Platform | Process-level execution isolation | Notes |
|---|---|---|
| **Linux (x86_64 / aarch64)** | ✅ Available, subject to the runtime probe below | The only implemented backend, [Sandlock](https://github.com/multikernel/sandlock) (Apache-2.0). AASM does not bundle it — see [Licensing and distribution](#licensing-and-distribution) below. |
| **macOS** | ❌ **Not supported.** `--isolation process` or `--isolation auto` is **refused** (`Boundary::Refused`) on this host, never silently downgraded to unconfined. | No backend targets macOS. This is not a roadmap statement — see ADR 0035 §8: "no Linux backend implies macOS or Windows support." |
| **Windows** | ❌ **Not supported.** Same refusal behavior as macOS. | No backend targets Windows. |

This intentionally does not read like the eBPF platform matrix in
[ADR 0033 §5.3](../adr/0033-canonical-governance-and-enforcement-architecture.md#53-the-verified-platform-matrix) —
eBPF is an *observation* mechanism with a macOS non-goal already recorded
there; execution isolation is a *confinement* mechanism with no macOS or
Windows implementation at all. Do not conflate the two absences.

### Runtime prerequisites on Linux

Selecting the backend on Linux is not automatic just because the host is
Linux — `aasm run` discovers a real executable and refuses with a specific,
diagnosable reason when it cannot:

| Failure | Diagnostic | Fix |
|---|---|---|
| Not on Linux | `the sandlock backend confines Linux processes; this host is <os>. No configuration on this host can change that answer.` | Use a Linux host, or `--isolation none`. |
| Backend not installed | `no sandlock executable on PATH; install it or set AA_SANDLOCK_BIN` | Install the Sandlock executable and put it on `PATH`, or point `AA_SANDLOCK_BIN` at it. |
| `AA_SANDLOCK_BIN` points at nothing | `AA_SANDLOCK_BIN names '<path>', which does not exist` | Correct the path or unset the variable to fall back to `PATH`. |
| Executable found but silent about its version | `` `<path>` did not report a version: <detail> `` | The binary at that path is not a compatible Sandlock build. |
| Backend measured but a required capability domain cannot prevent on this host | Reported per-domain in the isolation report; the launch is refused if the requirement's posture requires prevention | See [Requested vs. achieved](#requested-vs-achieved-the-report-shape); either relax the policy's posture for that domain, or accept `--isolation none`. |

Two capability domains — **syscall** and **name resolution** — are reported
`Unsupported` on this backend *by design*, not as a measurement gap: the
mechanism takes a denied syscall list while AASM's contract scopes a
requirement as a permitted set (the complement of a permitted set is
unbounded, so no denied list expresses it), and name resolution is redirected
to a pinned hosts file rather than decided per-lookup. **IPC** and
**credential** are reported `Partial` — see the [`/proc` caveat](#the-proc-caveat-on-credential-isolation)
above for credential specifically.

A capability is reported as able to prevent **only when a denial was actually
observed on this host** — not because the mechanism's documentation claims the
feature, the kernel release is new enough, or a security module is listed in
`/sys`. Those are inputs to the *message* an operator reads, never inputs to
the *verdict*.

A **native-Linux backend** (as opposed to the third-party Sandlock substrate)
is under active evaluation as a Go/No-Go benchmark spike
([AAASM-5713](https://lightning-dust-mite.atlassian.net/browse/AAASM-5713),
**in progress at the time of writing — no verdict exists yet**). This page
will be updated once that evaluation concludes; it makes no recommendation
about the outcome in the meantime.

## Troubleshooting

### Backend absent or incompatible

```console
$ aasm run exec --isolation process -- python agent.py
Error: refusing to launch: an execution-isolation boundary was requested and the `sandlock`
backend cannot be selected on this host — no sandlock executable on PATH; install it or set
AA_SANDLOCK_BIN.

There is no fallback. A launch that asked for a boundary and quietly ran without one would
report as governed while being unconfined, which is the failure this mode exists to prevent.
Install the backend, or re-run with `--isolation none` to launch unconfined deliberately.
```

**Fix.** Install the Sandlock executable (see [Licensing and distribution](#licensing-and-distribution))
and ensure it is on `PATH`, or set `AA_SANDLOCK_BIN` to its path. On macOS or
Windows there is no fix — no backend exists for those platforms; the only
options are running on Linux or launching with `--isolation none`.

### A required capability is refused rather than degraded

If policy states a domain's requirement with a posture that demands
prevention and the selected backend cannot provide it, the launch refuses
before the process starts — it does not launch with a weaker boundary than
requested. Check the domain's row in `aasm run --dry-run`'s per-capability
table for the exact reason, and either relax that domain's posture in policy
(if the operator's risk tolerance allows an explicit degradation) or accept
`--isolation none`.

### Explicit degradation

Where operator posture explicitly permits it, a planned control that is
configured but unavailable is reported as `Degraded`, carrying **both** the
planned level and the achieved level — never presented as equivalently
protected to a control that fully met its requirement. Look for the
`Degraded` entries in the isolation report's shortfalls section; each one
names what was planned and what was actually achieved.

### Proxy + isolation interaction

`--no-proxy` (transport mediation) and `--isolation` (process confinement)
are independent controls that answer different questions — whether the
tool's network traffic is inspected/mediated, and whether the process itself
is confined at the OS level. Requesting `--isolation process` does not
imply proxy mediation, and `--no-proxy` does not imply isolation is off.
Combining `--no-proxy` with `--isolation process` produces a process that is
OS-confined but whose network traffic is not inspected; combining the default
proxied launch with `--isolation none` produces a process whose traffic is
inspected but which is not OS-confined. Read both sections of `--dry-run`'s
output — `--- protection ---` for the proxy and `--- execution isolation ---`
for the boundary — rather than inferring one from the other.

## Licensing and distribution

**AASM distributes no execution-isolation backend binary.** The shipped
Sandlock backend is an external executable the operator installs separately
(currently pinned to Sandlock v0.8.6, Apache-2.0, from the upstream
[multikernel/sandlock](https://github.com/multikernel/sandlock) releases). No
AASM distribution channel — the GitHub Release tarballs, crates.io, the
Homebrew tap, the GHCR container images, or the shell installer — bundles,
downloads, or builds this backend on the operator's behalf; every channel
expects it as a pre-existing system dependency. Provenance (exact version,
release checksum, SPDX license, and whether AASM carries modifications — it
does not) is recorded in `metadata/isolation-backends.json` and verified by CI
against the upstream artifact's digest before any capability is measured.

A future backend with a materially different license or hosted-service terms
would require a separate product/legal review before entering an equivalent
built-in distribution path — see
[ADR 0035 §11](../adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md#11-backend-provenance-and-license-compatibility-are-release-inputs).

> **This is not legal advice.** This section and `metadata/isolation-backends.json`
> record an engineering and release-process requirement — which facts a
> backend must carry, and which changes require review before it ships — not
> a legal conclusion about any particular license or distribution channel.
> Whether a given license or hosted-service term is acceptable for a
> particular distribution is a decision for the product and legal owners.

## Quickstart: a governed, isolated launch

This walkthrough runs on a **Linux** host with the Sandlock backend installed
(see [Runtime prerequisites](#runtime-prerequisites-on-linux)). It is a
minimal governed launch of a program you own, previewed first and then run
with process-level isolation required.

1. Preview the launch without executing anything:

   ```console
   $ aasm run exec --isolation process --dry-run -- python agent.py
   ```

   Read the `--- execution isolation ---` section of the output: it states
   the requested capability set, the per-capability table (state, claim,
   evidence), any shortfalls or refusals, and the least-authority verdict for
   inherited credentials. If the backend cannot be selected on this host, the
   preview reports the refusal a live launch would raise and continues — it
   does not stop, because previewing from a machine that is not yet fully set
   up is exactly what `--dry-run` is for.

2. Once the preview looks right, run it for real:

   ```console
   $ aasm run exec --isolation process -- python agent.py
   ```

   If the backend is unavailable, this refuses outright rather than launching
   unconfined — see [Troubleshooting](#troubleshooting) above.

3. To require *some* isolation without committing to `process` specifically —
   for example on a fleet where a future backend class might apply — use
   `--isolation auto` instead. Today it resolves to `process`, and it refuses
   under the same conditions.

For the full flag reference, see the [`aasm run` CLI reference](../cli/run.md).
For the underlying architectural decision, see
[ADR 0035](../adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md).
