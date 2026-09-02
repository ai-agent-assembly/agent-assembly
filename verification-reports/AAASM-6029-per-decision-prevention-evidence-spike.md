# AAASM-6029 — a per-decision prevention evidence channel for `IsolationBackend`

Whether any shipped or candidate isolation backend can deliver a per-decision
record to the AASM supervisor, what the `IsolationBackend` contract would need
to carry it, and whether it is worth building now.

- **Ticket:** [AAASM-6029](https://lightning-dust-mite.atlassian.net/browse/AAASM-6029)
  (Spike) · follow-up from [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534)'s
  re-baseline, gap **G1** · **Epic:** [AAASM-5526](https://lightning-dust-mite.atlassian.net/browse/AAASM-5526)
- **Compiled against** `remote/main` at `48d7b8bc3`
- **Sibling artifacts:** [`AAASM-5534-host-wide-mediation-rebaseline.md`](AAASM-5534-host-wide-mediation-rebaseline.md),
  [`AAASM-5527-capability-coverage-matrix-and-threat-model.md`](AAASM-5527-capability-coverage-matrix-and-threat-model.md)

## Verdict

**Do not build a per-decision evidence channel now.** One follow-up is worth
opening, and it is not AASM implementation work: the only mechanism in the
shipped set that *already produces* per-decision records is Sandlock, and it
produces them behind an interface AASM does not use. Everything else costs a
new enforcement architecture, a kernel-floor raise, or a privileged helper
daemon, to buy a claim that only strengthens on runs where the agent actually
attempted something forbidden.

The single most useful finding is a correction to the gap's own framing:

> **The `IsolationBackend` contract is not the blocker, and no channel needs to
> be added to it.** `EvidenceKind::Decision` already exists, `evidence()` is
> already called after `wait_for_exit`, and the whole consuming path from a
> `Decision` record to a `Denied before execution` claim is already built *and
> already under test*. A backend that could buffer per-decision records during
> a run could emit them today, through the accessor that already exists,
> without one line of contract change.

What the contract *does* lack is an honesty field — a typed way for a backend
to say "I structurally cannot report decisions on this domain" rather than
leaving that fact in three module-doc paragraphs. A shape for it is proposed
below, together with the argument for **not landing it until a producer
exists**.

## Why this file lives here

Same placement decision as [AAASM-5527](AAASM-5527-capability-coverage-matrix-and-threat-model.md),
[AAASM-5528](AAASM-5528-public-claim-inventory.md) and the 5534 re-baseline:
this is a point-in-time evidence artifact, not operator prose, and a page under
`docs/src/` is unreachable unless registered in `docs/src/SUMMARY.md`.

It is deliberately **not** an ADR, and it edits none. The relevant durable
record already exists — [Core ADR 0035](../docs/src/adr/0035-agent-execution-isolation-and-pluggable-enforcement-backends.md)'s
AAASM-5801 amendment already defers exactly this question in its own words, and
[`docs/src/security/execution-isolation.md`](../docs/src/security/execution-isolation.md)
already states the gap to operators. Where this spike concludes a ratified
record should change, it says so as a recommendation for an **amendment**,
following the disposition 5534's F2 already set.

## Method, and what could not be measured

Every claim about AASM code below is grounded in a file read at `48d7b8bc3`.

| Source | What it settles |
|---|---|
| `aa-isolation/src/backend.rs`, `evidence.rs`, `capability.rs`, `plan.rs`, `report.rs` | The contract: what `evidence()` returns and when, what `EvidenceKind::Decision` already does, what `with_evidence` does with it |
| `aa-isolation/tests/evidence.rs:52-143` | That the *consuming* half of G1 is already built and tested |
| `aa-isolation-native/src/backend.rs`, `seccomp.rs`, `rules.rs`, `host.rs`, `probe.rs` | The Linux native mechanism: `SECCOMP_RET_KILL_PROCESS`, Landlock ABI floor v3, the control/test probe pairs |
| `aa-isolation-sandlock/src/lib.rs`, `backend.rs`, `lower.rs` | That AASM drives Sandlock as an external executable over argv, and which flags it emits |
| `aa-isolation-macos-vm/src/lib.rs`, `aa-isolation-vm-proto/src/lib.rs` | That the macOS route runs the *native* launcher inside a Linux guest over a versioned vsock protocol, and what `evidence()` returns there |
| `metadata/isolation-backends.json` | Pinned mechanism versions: Sandlock v0.8.6 (digest-verified), guest kernel `6.6.71` |
| `Cargo.lock`, `docs.rs/landlock/0.4.7` | That the pinned Rust binding is `landlock 0.4.7` and what it exposes |
| `seccomp(2)`, `seccomp_unotify(2)` (man7.org), kernel.org Landlock userspace API | Kernel mechanism capability |

**Two honest limits on this survey.**

1. **No Linux host was available in this session.** Every kernel-mechanism
   statement below is derived from the kernel's own documentation and from the
   AASM code that calls it — it is *documentation-derived*, not measured on a
   host. Where a claim would change the recommendation if wrong, it is flagged.
   The ticket's phrasing ("does Landlock/seccomp produce any observable
   per-decision signal *on this host*") cannot be answered by measurement from
   a macOS session, and the answer below is not dressed up as one.
2. **Sandlock's internals are read from its published documentation at the
   pinned tag `v0.8.6`**, not from its source or from the installed binary. The
   AASM-side facts (which flags AASM emits, that it is driven as an executable)
   *are* read from AASM's own code.

## What the gap actually is, precisely

`supports_prevention_claim` is false for every capability domain on every
shipped backend, always. That is correct and honest, and it is asserted by
negative tests in all three backends (`aa-isolation-native/src/backend.rs:1246`,
`aa-isolation-sandlock/src/backend.rs:1085`, and the `linux_confinement*` /
`adversarial_boundary_native_linux` suites).

Decomposing the gap into its parts is what makes the cost tractable, because
three of the four parts are already done:

| Part | State at `48d7b8bc3` |
|---|---|
| **A vocabulary for a per-decision fact** | **Done.** `EvidenceKind::Decision` — *"The control produced a decision about a specific action. The only grade that can support a prevention claim."* (`evidence.rs:43-46`) |
| **A predicate that consumes it correctly** | **Done.** `supports_prevention_claim` requires `kind == Decision` *and* `claim.is_prevention()`; `IndependentVerification` deliberately does not satisfy it (`evidence.rs:255-263`) |
| **A report path that turns it into a product claim** | **Done.** `IsolationReport::with_evidence` downgrades any prevention term to `Observed` unless `supports_prevention_claim` holds (`report.rs:957-963`) |
| **A delivery point on the trait** | **Done, and unrecognised as such.** `evidence(&handle)` is called *after* `wait_for_exit` returns (`aa-cli/src/commands/run.rs:3321`). A backend that buffered decisions during the run would emit them from there |
| **A mechanism that produces one** | **Missing. This is the entire gap.** |

The consuming half is not hypothetical — it is pinned by test. `aa-isolation/tests/evidence.rs:75-85`
constructs a `Decision` record by hand and asserts the full promotion:

```rust
assert!(evidence.supports_prevention_claim(domain));
assert_eq!(evidence.claim_for(domain), ClaimTerm::DeniedBeforeExecution);
```

and `aa-integration-tests/tests/adversarial/mod.rs:1054` asserts the same
through a whole `IsolationReport`. So the cost of G1 is **entirely in the
mechanism**, and zero in the contract's data model or its consumers. Any
estimate that budgets contract work is overstating the price.

### Why the existing probes cannot close it

Both Linux backends already measure *real denials* with a control/test pair at
`discover()` — the same confined command run twice differing by exactly one
grant, counted as a denial only when the control run produced the effect and
the test run did not (`aa-isolation-native/src/probe.rs`, module doc). A reader
will reasonably ask why that is not already a decision record.

It is not, for a reason the type system already encodes: the probe measures a
*different program* performing a *different action* at a *different time* — at
backend construction, not during the confined run. It establishes what the host
can do, which is what gates `can_prevent()`. It says nothing about what any
control decided during *this* run. That is exactly what
`EvidenceKind::IndependentVerification` is for, and `evidence.rs:255-258`
states the rule plainly: corroboration presupposes the decision it
corroborates; without one, an out-of-band probe showing an action failed does
not establish that *this* control is why.

## Survey: what each backend's mechanism can actually report

### `aa-isolation-native` — Landlock + seccomp-BPF on Linux

Four candidate channels exist. None is usable as shipped.

| Channel | What it would deliver | Why it is not usable today |
|---|---|---|
| **Landlock audit records** (`AUDIT_LANDLOCK_ACCESS`) | A real per-denial record: the denied access right, the object, the originating domain | Requires **Landlock ABI 7 / Linux 6.15**. The backend's own floor is **ABI v3 / Linux 6.2** (`rules.rs:155-163`), so requiring audit would raise the kernel floor by nine releases. And the records go to the **kernel audit subsystem** — host-wide netlink, needing `CAP_AUDIT_READ`, correlated to the confined process only by PID. See the cost note below |
| **seccomp audit records** (`type=1326`) | Which syscall was refused | Same audit-subsystem path, plus `SECCOMP_RET_KILL_PROCESS` is logged only *"if that action appears in the `actions_logged` file"* and auditing is enabled (`seccomp(2)`) — a host-wide sysctl AASM does not own |
| **`SECCOMP_RET_TRAP`** | `SIGSYS` to the offending thread, syscall not executed | The record would be produced **inside the confined, untrusted process**. Under Core ADR 0035's threat model the agent is untrusted; a denial record self-reported by the thing being confined is not evidence. Rejected on threat-model grounds, not cost |
| **`SECCOMP_RET_USER_NOTIF`** | The real answer for the `Syscall` domain: a synchronous, pre-effect notification per filtered syscall, delivered to the supervisor. Linux 5.0+ | A new enforcement architecture, not an evidence add-on. See below |

**The `SECCOMP_RET_USER_NOTIF` trade, stated as a trade.** The AAASM-5801
amendment already names this as the route that "could earn a stronger claim
later ... but that is explicitly deferred". Four costs it does not enumerate:

1. **It weakens the boundary it is meant to evidence.** The filter's default
   action today is `SECCOMP_RET_KILL_PROCESS` — *"immediate termination of the
   process, with a core dump. The system call is not executed"* (`seccomp(2)`),
   and it kills the whole thread group. Moving the default action to
   `USER_NOTIF` turns a denied syscall from **process death** into a
   **recoverable error the untrusted program can catch and route around**. When
   no supervisor is attached, *"the filter returns `ENOSYS`"* — the effect does
   not happen, so this is not fail-open in the effect sense, but the agent
   survives to try something else. Under a threat model where the agent is
   untrusted, that is a real weakening purchased with evidence.
2. **The listener fd has to escape the confined process.** The launcher
   installs the filter **on itself, before `execve`** (`seccomp.rs` module doc)
   — deliberately, because a seccomp filter is inherited across `execve`. So
   the notification fd is created inside the process that is about to become
   the confined program, and must be passed out to the supervisor over a unix
   socket with `SCM_RIGHTS` before the `execve`. That is a new host↔confined
   channel in a design whose stated property is that "the supervisor stays
   structurally outside the boundary" (`backend.rs` module doc, Core ADR 0035 §5).
3. **One listener per thread, ever.** *"At most one seccomp filter using the
   `SECCOMP_FILTER_FLAG_NEW_LISTENER` flag can be installed for a thread"*
   (`seccomp(2)`). This forecloses composing AASM's notifier with any other.
4. **A supervisor thread per launch, plus TOCTOU handling.** Notifications must
   be received and answered or the target blocks; pointer arguments must be
   read out of the target's memory under the `SECCOMP_IOCTL_NOTIF_ID_VALID`
   re-check. This is the standard, well-known hard part of `seccomp_unotify(2)`.

**Cost note on the audit route.** Reading kernel audit records requires a
capability the supervisor deliberately does not hold. AASM has already met this
exact shape once: Core ADR 0033 §5.2 puts `CAP_BPF` in a separate privileged
daemon, `aa-ebpf-loaderd`, precisely so `aa-runtime` holds none. The audit route
is therefore not "parse a log file" — it is "ship a second privileged helper
daemon, with its own socket, lifecycle, install story and attack surface,"
which then has to solve host-wide record filtering and PID correlation (the
PID-reuse question 5534 left open under G-Linux). Correct scoping of that work
is an Epic, not a subtask.

**Aarch64 note.** The seccomp filter is a hand-built cBPF program against the
x86_64 syscall table, so the `Syscall` domain reports `Unsupported` on aarch64
entirely (5534's G4). Any `USER_NOTIF` work inherits that cliff.

**One thing the supervisor *can* already see, and why it is not enough.** With
`SECCOMP_RET_KILL_PROCESS`, a filtered syscall kills the process, and
`wait_for_exit` returns `ExitDisposition::NoCode` (a signal death). That is an
*aggregate* fact — "something the filter refused happened" — with no syscall,
no argument and no timestamp. Recording it as `Decision` would be precisely the
promotion `aa-isolation-native/src/backend.rs:34-36` names and refuses:
manufacturing a decision record from how the program exited. It is not, and
must not become, a per-decision record.

### `aa-isolation-sandlock` — the record already exists, on the other side of the interface

This is the survey's most actionable finding.

Sandlock's own documentation at the pinned tag `v0.8.6` states it confines code
using *"Landlock (filesystem + network + IPC), seccomp-bpf (syscall filtering),
and **seccomp user notification** (resource limits, IP enforcement, /proc
virtualization)"*. It exposes a `policy_fn` callback that *"inspect[s] syscall
events at runtime"*, receiving per-event detail — syscall name, category, PID,
network destination for `connect`/`sendto`/`bind`, and `argv` for `execve` —
and returning an `allow` / `deny` / `audit` verdict.

**So a per-decision record with the right shape already exists inside the
mechanism AASM ships against.** The obstruction is entirely the interface:

- `policy_fn` is a **library** API (Rust and Python), with **no CLI exposure**.
- AASM drives Sandlock as an **external executable over argv**
  (`aa-isolation-sandlock/src/lower.rs` — `--fs-read`, `--fs-write`,
  `--net-allow`, `--max-memory`, `--max-processes`, `--clean-env`, `--env`,
  `--cwd`, `--allow-degraded`, and nothing else), and there is no documented
  CLI flag that emits an event stream, audit log or event fd.
- The `ps` / `inspect` / `kill` subcommands report sandbox metadata and
  effective policy — `inspect` returns policy as JSON or TOML — but,
  per the same documentation, not per-decision events. **Unverified against the
  installed binary**; a `sandlock inspect` probe on a real Linux host is the
  cheapest possible next measurement and is listed as a next step rather than
  asserted here either way.

Two routes exist, and they are very different sizes:

1. **Ask upstream for a CLI event stream** (`--events-fd`, JSON lines).
   Sandlock is Apache-2.0, actively developed, and already computes the record
   internally. This costs AASM an upstream issue and, if accepted, a small
   consuming change on a `Decision`-emitting path that already has its
   consumers built. **This is the only route in the whole survey where the
   record already exists and nobody has to build a mechanism.**
2. **Link Sandlock as a library.** Technically the shortest path to
   `policy_fn`, and architecturally the most expensive: it drops a third-party
   confinement mechanism into AASM's cargo dependency graph and **rewrites the
   provenance story**. Today `metadata/isolation-backends.json` records
   Sandlock as an operator-installed executable across every channel, and the
   file's own reason for existing is that a prebuilt binary "never enters that
   graph, so cargo-deny never evaluates its license." Linking inverts that: the
   `cargo-deny` gate would start covering it, the `check-backend-license-compliance.sh`
   row would need rewriting, and "AASM distributes nothing" stops being true
   for the OSS channel. Not recommended.

### `aa-isolation-macos-vm` — not a separate mechanism problem

The macOS backend does not have its own confinement mechanism to survey. It
boots a Linux guest under Virtualization.framework and runs
**`aa-isolation-native`'s own launcher inside it** over a versioned vsock
protocol (`aa-isolation-vm-proto`, `PROTOCOL_VERSION = 1`). So:

- **Its per-decision ceiling is the Linux native ceiling**, evaluated against
  the *guest* kernel — pinned at **`6.6.71`** in
  `metadata/isolation-backends.json`, which is **below the 6.15 Landlock audit
  floor**. On that kernel there are no Landlock audit records to forward.
- The guest is aarch64 on Apple Silicon, so `syscall_filter` is `None` on every
  launch and the `Syscall` domain is `Unsupported` — the `USER_NOTIF` route has
  nothing to attach to there either.
- **The wire is the easy part, and it is already the right shape.** The
  protocol has a precedent for carrying evidence input: `LaunchOutcome`'s
  `implicit_grants` field, documented as *"evidence input ... the caller must
  record it under an existing `ClaimTerm`, not a new one."* Adding a
  `decisions: Vec<...>` field or a new message means bumping
  `PROTOCOL_VERSION` — and by construction both endpoints then fail to compile
  rather than misinterpreting each other. If a guest-side producer ever exists,
  transporting its output is a small, well-guarded change.

The honest summary for macOS: **the guest can report exactly what the Linux
native backend can report, which is nothing, on a kernel nine releases below
where that would change.** The ticket's own risk note anticipated this; the
finding confirms it, but for a more specific reason than "guest visibility is
limited."

## The contract change, if one is warranted

### No channel is needed

Restating the finding from the top, because it is the part most likely to be
mis-scoped by a follow-up ticket: **`IsolationBackend` needs no new method, no
callback, and no streaming channel to carry per-decision evidence.**
`evidence(&handle)` is invoked after `wait_for_exit` has returned
(`run.rs:3321`), so a backend that accumulated decision records during the run
returns them from the accessor that already exists. `EnforcementEvidence`
already has `record()`/`with_record()`, and `EvidenceKind::Decision` already
means the right thing.

A *live* channel — one that hands decisions to the supervisor while the process
runs — is only required if the supervisor must **participate in the decision**.
That is `SECCOMP_RET_USER_NOTIF`, and it is an enforcement feature, not an
evidence feature. Conflating the two is what makes this gap look like a
contract problem when it is a mechanism problem.

### An honesty field is the one thing genuinely missing

The ticket asks that a backend which cannot produce a per-decision record "be
able to honestly say so, not silently omit." Today it cannot. The fact lives in
prose — three near-identical module-doc paragraphs in `aa-isolation-native`,
`aa-isolation-sandlock` and `aa-isolation/src/mock.rs` — and in negative test
assertions. Nothing typed distinguishes:

- *"this mechanism cannot report decisions on this domain, ever"* from
- *"it can, and nothing was denied during this run"*.

Both render as an absence of `Decision` records, and both collapse to
`ClaimTerm::Unmeasured`. `Unmeasured` is honest for each of them, but they are
different facts and an operator reading a report cannot tell which they have.

The smallest change that fixes it is **one field on `CapabilityReport`**,
alongside the `Mediation` / `DecisionTiming` / `Synchrony` axes that already
sit there:

```rust
/// Whether this capability can deliver a record of an individual decision to
/// the supervisor — a *reporting* property, independent of whether the control
/// decides anything (`Mediation`) or when (`DecisionTiming`).
#[non_exhaustive]
pub enum DecisionReporting {
    /// The mechanism delivers no record of an individual decision. The honest
    /// default: the kernel refuses the confined process's own syscall and the
    /// error returns to that process.
    None,
    /// The mechanism reports that decisions occurred, without identifying
    /// them individually (e.g. a process killed by a seccomp filter).
    Aggregate,
    /// The mechanism delivers a record per decision, attributable to this run.
    PerDecision,
}
```

Properties that make it the right shape:

- **Default `None` means no backend has to fake anything.** Adding the field
  gives all three shipped backends the honest answer for free, with no
  per-backend claim to write.
- **It separates two axes the current model conflates.** `Mediation::Enforce`
  says the control decides; it does not say anyone learns what it decided.
- **It is discoverable before launch**, so a future requirement of the shape
  "I need per-decision evidence for this domain" could be refused by
  `negotiate` before spawn — the same fail-closed shape everything else in this
  contract uses.
- **It gives `can_observe()` a real basis** rather than the inference it makes
  today (see F1 below).

### And it should not land yet

Recommend **not** adding it until a producer exists, on the repo's own
established reasoning. Core ADR 0035's AAASM-5751 amendment records why four
capability domains stay `PolicyCannotExpress` rather than getting a speculative
schema: *a speculative schema is a public contract that cannot be withdrawn,
while a named gap can be closed at any time.* A `DecisionReporting` enum landed
today would have exactly one inhabited variant, no producer and no consumer —
a public shape ratified before the mechanism that would prove it right. The gap
is currently named in prose in three places and in this document; that is the
cheaper, reversible state.

The concrete trigger for landing it is stated under [Reconsideration
triggers](#reconsideration-triggers): it lands **with** the first producer, in
the same change, not before.

**No proof-of-concept was built for this spike**, deliberately. The only thing
there is to prototype is the schema above, and building it would contradict the
finding.

## Cost against value

**What closing G1 actually buys.** With a `Decision` record carrying a
prevention term, `claim_for` returns `DeniedBeforeExecution` for that domain
instead of being downgraded to `Observed` by `report.rs:957`. That is the
product's strongest enforcement claim, and it would be genuinely earned.

**Why that is narrower than it sounds.** A decision record only exists when the
agent *attempted a forbidden action and was refused*. On a well-behaved run —
the overwhelming majority — no control decides anything, no record is produced,
and the domain's claim stays `Unmeasured` or `Observed` exactly as it does
today. Per-decision evidence therefore does **not** raise the claim on a
typical run. It raises it on the runs where something was blocked.

That is real value for incident review, for an adversarial conformance suite,
and for any future product claim of the form "AASM blocked N actions." It is
not a general uplift to what every governed run may claim, and it should not be
scoped or sold as one.

**Costs, ordered.**

| Route | Cost | Buys |
|---|---|---|
| Upstream Sandlock CLI event stream | An upstream issue; small consuming change if accepted. Not on AASM's critical path | `Decision` records for Sandlock's domains, on the backend `--isolation auto` tries first |
| Link Sandlock as a library | Medium engineering; **rewrites the licence/provenance model** and puts a third-party mechanism in the cargo graph | The same records, at a much worse architectural price |
| `SECCOMP_RET_USER_NOTIF` in `aa-isolation-native` | Large: new host↔confined fd handoff, per-launch supervisor thread, TOCTOU handling, **and a deliberate weakening of the default kill action**. x86_64 only | `Decision` records for the `Syscall` domain only |
| Landlock audit reader | Large: kernel floor v3→v7 (Linux 6.2→6.15), plus a **second privileged daemon** on the `aa-ebpf-loaderd` model, plus host-wide filtering and PID correlation | `Decision` records for the filesystem domains, on 6.15+ hosts only |
| macOS VM | The Linux cost, plus a protocol bump, plus a guest-kernel upgrade past 6.15 | Nothing until a Linux producer exists |

Against a benefit that materialises only on runs where an agent misbehaved, and
with 5534's own gap list still carrying **G6** — adversarial conformance at
three of seventeen attack classes, which it calls *"the highest-value remaining
verification work"* — none of the middle three rows is the right next thing to
build.

## Recommendation

1. **Close AAASM-6029 as a completed spike** with this artifact as its
   deliverable. The finding is *not worth building now*, which the ticket
   explicitly names as a valid outcome.
2. **Open one follow-up, and make it an upstream ask, not AASM implementation
   work**: request a per-decision event stream on Sandlock's CLI
   (`--events-fd` / JSON lines), and — first, because it is nearly free — probe
   `sandlock inspect` on a real Linux host to confirm whether decision state is
   already reachable without linking. Small; blocked on nobody; the only route
   where the record already exists.
3. **Do not open implementation tickets** for `SECCOMP_RET_USER_NOTIF`, a
   Landlock audit reader, or a macOS guest decision channel. Record them as
   deferred with the triggers below.
4. **Do not land `DecisionReporting` on its own.** It lands with the first
   producer, in the same change.
5. **Route the incidental findings below** to their own small tickets. Neither
   is part of G1 and neither should be folded into it.
6. **Leave Core ADR 0035 alone.** Its AAASM-5801 amendment already defers this
   question accurately. If the Epic owner wants the deferral to carry the four
   `USER_NOTIF` costs enumerated here, that is an **amendment to 0035**, not a
   new ADR and not an edit to the existing amendment text by this spike.

### Reconsideration triggers

Named, so the deferral is a decision with an expiry rather than a shrug —
matching how Core ADR 0035 already uses reconsideration triggers.

1. **Sandlock exposes per-decision events on its CLI.** Reconsider immediately:
   the cost collapses to a consuming change against consumers that already
   exist.
2. **A product claim requires per-action prevention.** If any published claim,
   contract or compliance requirement needs "AASM denied *this* action," the
   value side of this trade changes and the `USER_NOTIF` cost may become worth
   paying. Today no consumer requires it — `supports_prevention_claim` has one
   production consumer, `report.rs:957`, and its only job is to *refuse* a
   claim.
3. **The supported Linux kernel floor moves to 6.15+ for other reasons.** The
   Landlock audit route's dominant cost is the floor raise; if that is paid
   elsewhere, only the privileged-reader daemon remains, and the trade should
   be re-run.
4. **A privileged AASM helper daemon ships on Linux for another reason.** The
   audit route's second cost is the daemon. If one exists, adding an audit
   reader to it is materially cheaper than standing one up.
5. **A new backend is proposed whose mechanism reports decisions natively.**
   Then `DecisionReporting` lands with it, as designed above.

## Incidental findings — reported, not fixed

Both were found while compiling this spike, are outside AAASM-6029's scope, and
are recorded here rather than changed — the AAASM-5527/5534 precedent.

### F1 — `can_observe()` infers observation from enforcement, and the inference is false in this system

`CapabilityReport::can_observe()` (`aa-isolation/src/capability.rs:527-534`)
carries the doc comment *"True for enforcing controls as well: enforcing
implies knowing."* In this system, enforcing does **not** imply knowing: that
is the entire content of G1. Every shipped backend enforces and reports no
per-action evidence at all.

It is load-bearing, not decorative. `plan.rs:489-492` refuses a
`RequirementIntent::Observe` requirement with
`RefusalReason::NoEvidenceProduced` when `!can_observe()`. Because
`can_observe()` returns true for any available enforcing control,
`NoEvidenceProduced` **can never fire for an enforcing domain** — so an
`Observe` requirement against, say, `FilesystemWrite` on `aasm-native` is
accepted and lowered to `RequirementOutcome::Observed`, while the backend
delivers no per-action observation whatsoever. `ControlRequirement::observe`'s
own doc (`spec.rs:272-273`) promises *"a requirement that the domain produce
evidence, refusing the launch if it cannot"*, and for enforcing domains that
promise is not kept. `plan.rs:522-530`'s `achieved()` uses the same predicate
to describe a degraded requirement as `AchievedControl::Observed`.

**Severity: latent, not live.** `ControlRequirement::observe` is constructed
only in tests and in the adversarial harness at `aa-integration-tests/tests/adversarial/mod.rs:456`
— no production policy-lowering path builds an `Observe` requirement today, so
nothing in a shipped run currently takes the over-accepting branch. The post-run
claim also stays honest independently, because `claim_for` only counts runtime
records.

**Suggested disposition:** a small Bug under Epic 5526 to correct the doc
comment, and to note that `can_observe()`'s basis becomes real the day
`DecisionReporting` (or an equivalent) exists. Fixing the *predicate* before
then would refuse `Observe` requirements nothing constructs, which is churn.
This is the pre-launch twin of G1 and is closed by the same field.

### F2 — `MacosVmBackend::evidence()` returns no records at all

`aa-isolation-macos-vm/src/lib.rs:497-506` returns
`EnforcementEvidence::new(...)` with an empty record vector. Not merely no
`Decision` records — **no `Configured`, `Installed` or `Exercised` records
either**, where `aa-isolation-native` and `aa-isolation-sandlock` each emit
several per run (measured host facts, permitted path scope, syscall filter
state, `/proc` scope, residual ambient authority, inherited descriptors).

The code says so itself and attributes the work: *"`Configured`/`Installed`/`Exercised`
evidence built from a run's own `implicit_grants` and grant set is real, scoped
follow-on work (AAASM-5813 AC4/evidence reporting), not yet built this pass."*

The consequence is not a false claim — an empty evidence object is
`Unmeasured` everywhere, which `aa-isolation/tests/evidence.rs:137-143` pins as
the correct reading of absence. The consequence is that an operator running
`aasm run --isolation-backend aasm-macos-vm` gets an isolation report with
nothing in it, so a real, hardware-qualified guest boundary reads exactly like
one that did nothing.

**This is adjacent to G1, not part of it**, and it is much cheaper: every fact
those records would carry is already known host-side or already on the wire.
**Suggested disposition:** confirm AAASM-5813's status and, if it is closed,
open a Bug for the residual — this is the one gap in this document that is
worth building now.

## Scope fences

Three adjacent questions are **not** in this spike and must not be absorbed
into it:

- **The adversarial conformance gap (5534's G6)** —
  [AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532)'s
  own acceptance criterion. 5534 calls it the highest-value remaining
  verification work, and this spike's cost/value comparison assumes it stays
  ahead of G1 in priority.
- **`--isolation auto` selection** —
  [AAASM-5808](https://lightning-dust-mite.atlassian.net/browse/AAASM-5808),
  Done. A `DecisionReporting` axis would eventually be selection-relevant; that
  is a later question and not reopened here.
- **The four `PolicyCannotExpress` domains (5534's G3)** — recorded as accepted
  measured risk in Core ADR 0035's AAASM-5751 amendment. This spike borrows that
  amendment's *reasoning* about speculative schema; it does not reopen its
  decision.
